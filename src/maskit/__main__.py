"""Maskit entry point."""

from __future__ import annotations

import logging
import os
import signal
import sys
from contextlib import AsyncExitStack
from pathlib import Path

import anyio
import uvicorn
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage

from maskit.config import load_config
from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import ArgumentGuardrail, ArgumentInjection, MaskingRule
from maskit.masking.store import MaskingStore
from maskit.oauth.handler import OAuthCallbackServer
from maskit.proxy.core import ProxyState, TargetState, run_proxy_for_target
from maskit.proxy.http_downstream import create_mcp_app
from maskit.proxy.manager import TargetManager, _build_upstream_config
from maskit.proxy.upstream import connect_upstream
from maskit.web.app import create_app

logger = logging.getLogger(__name__)


async def _flush_loop(engine: MaskingEngine, shutdown_event: anyio.Event):
    """Periodically flush pending alias writes to the database."""
    while not shutdown_event.is_set():
        await anyio.sleep(1.0)
        if engine.has_pending_writes:
            try:
                await engine.flush_pending()
            except Exception:
                logger.exception("Failed to flush aliases to database")
    # Final flush on shutdown
    if engine.has_pending_writes:
        try:
            await engine.flush_pending()
        except Exception:
            logger.exception("Failed final flush of aliases to database")


async def _graceful_shutdown(
    state: ProxyState,
    shutdown_event: anyio.Event,
    web_server,
    mcp_server,
    callback_web_server,
    tg,
    drain_timeout: float,
    flush_timeout: float,
) -> None:
    """Coordinate graceful shutdown with timeout enforcement.

    Shutdown sequence:
    1. Stop accepting new requests (servers marked for exit)
    2. Drain in-flight requests (ResponseDispatcher notifies waiters)
    3. Wait for flush loops to complete
    4. Close upstream connections
    5. Task group cancellation (any remaining tasks)
    """
    logger.info("Starting graceful shutdown sequence")

    # Stage 1: Stop accepting new requests
    logger.info("Stage 1/4: Stopping request acceptance")
    web_server.should_exit = True
    mcp_server.should_exit = True
    callback_web_server.should_exit = True

    # Stage 2: Drain in-flight requests
    logger.info(f"Stage 2/4: Draining in-flight requests ({drain_timeout}s timeout)")
    with anyio.move_on_after(drain_timeout):
        for target_state in state.targets.values():
            # Notify all waiting HTTP clients to abort
            target_state.response_dispatcher.shutdown()

            # Close downstream streams (prevents new messages from clients)
            if target_state.ds_read_send:
                await target_state.ds_read_send.aclose()

    # Stage 3: Wait for flush loops to complete
    logger.info(f"Stage 3/4: Waiting for database flushes ({flush_timeout}s timeout)")
    with anyio.move_on_after(flush_timeout):
        # Signal shutdown to flush loops
        shutdown_event.set()

        # Give flush loops time to complete final flush
        await anyio.sleep(0.5)

        # Check if flushes completed
        pending_count = sum(
            ts.engine.has_pending_writes for ts in state.targets.values()
        )
        if pending_count > 0:
            logger.warning(f"{pending_count} targets still have pending writes")

    # Stage 4: Cancel remaining tasks (relay loops, servers)
    logger.info("Stage 4/4: Cancelling remaining tasks")
    tg.cancel_scope.cancel()


async def async_main():
    from maskit.logging_config import setup_logging
    from maskit.cli import parse_args

    setup_logging()
    logger = logging.getLogger(__name__)

    args = parse_args()
    config = load_config(
        path=args.config_path,
        web_port=args.web_port,
        mcp_port=args.mcp_port,
        oauth_port=args.oauth_port,
        store_path=args.store_path,
    )
    bind_host = os.environ.get("MASKIT_HOST", "127.0.0.1")

    # Shutdown configuration
    SHUTDOWN_TIMEOUT = float(os.environ.get("MASKIT_SHUTDOWN_TIMEOUT", "30"))
    DRAIN_TIMEOUT = 5.0  # Time to wait for in-flight requests
    FLUSH_TIMEOUT = 3.0  # Time to wait for database flushes

    store = await MaskingStore.create(config.store_path)

    state = ProxyState()
    state.store = store
    state.mcp_port = config.mcp_port

    # Create per-target state
    for name, target_config in config.targets.items():
        rules = [
            MaskingRule(
                tool_name=r.tool_name,
                field_path=r.field_path,
                alias_prefix=r.alias_prefix,
                action=r.action,
            )
            for r in target_config.rules
        ]
        db_rules = await store.get_rules(target_name=name)
        rules.extend(db_rules)

        engine = MaskingEngine(rules, store, target_name=name)
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()

        for g in target_config.guardrails:
            engine.add_guardrail(ArgumentGuardrail(
                tool_name=g.tool_name, argument_name=g.argument_name,
                match_type=g.match_type, pattern=g.pattern, message=g.message,
            ))
        for i in target_config.injections:
            engine.add_injection(ArgumentInjection(
                tool_name=i.tool_name, argument_name=i.argument_name,
                value=i.value, mode=i.mode,
            ))

        hidden = await store.get_hidden_tools(target_name=name)

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](32)

        target_state = TargetState(
            name=name,
            engine=engine,
            hidden_tools=set(hidden),
            ds_read_send=ds_read_send,
            ds_read_recv=ds_read_recv,
        )
        state.targets[name] = target_state

    state.config_target_ids = set(config.targets.keys())

    # Load active marketplace servers from DB
    marketplace_configs: dict[str, dict] = {}
    installed = await store.get_installed_servers(active_only=True)
    for record in installed:
        server_id = record["id"]
        if server_id in state.targets:
            continue

        engine = MaskingEngine([], store, target_name=server_id)
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()
        hidden = await store.get_hidden_tools(target_name=server_id)
        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](32)

        target_state = TargetState(
            name=server_id,
            engine=engine,
            hidden_tools=set(hidden),
            ds_read_send=ds_read_send,
            ds_read_recv=ds_read_recv,
        )
        state.targets[server_id] = target_state
        marketplace_configs[server_id] = record["config"]

    shutdown_event = anyio.Event()

    # Shared OAuth callback server (always running)
    callback_server = OAuthCallbackServer(port=config.oauth_port)
    callback_app = callback_server.create_app()
    callback_uvicorn_config = uvicorn.Config(
        callback_app,
        host=bind_host,
        port=config.oauth_port,
        log_level="warning",
        log_config=None,
    )
    callback_web_server = uvicorn.Server(callback_uvicorn_config)
    callback_web_server.install_signal_handlers = lambda: None
    state.callback_server = callback_server

    logger.info("Maskit proxy starting")
    logger.info(f"Dashboard: http://{bind_host}:{config.web_port}")
    logger.info(f"OAuth callback: http://{bind_host}:{config.oauth_port}/callback")
    logger.info("MCP servers:")
    for name in state.target_names:
        logger.info(f"  {name}: http://{bind_host}:{config.mcp_port}/{name}/mcp")

    web_app = create_app(state)
    mcp_app = create_mcp_app(state)

    uvicorn_config = uvicorn.Config(
        web_app,
        host=bind_host,
        port=config.web_port,
        log_level="warning",
        log_config=None,
    )
    web_server = uvicorn.Server(uvicorn_config)
    web_server.install_signal_handlers = lambda: None

    mcp_uvicorn_config = uvicorn.Config(
        mcp_app,
        host=bind_host,
        port=config.mcp_port,
        log_level="warning",
        log_config=None,
    )
    mcp_server = uvicorn.Server(mcp_uvicorn_config)
    mcp_server.install_signal_handlers = lambda: None

    try:
        async with AsyncExitStack() as stack:
            # Connect all upstream targets
            upstream_streams: dict[str, tuple[
                MemoryObjectReceiveStream[SessionMessage | Exception],
                MemoryObjectSendStream[SessionMessage],
            ]] = {}

            failed_targets = []
            for name, target_state in state.targets.items():
                if name in config.targets:
                    target_config = config.targets[name]
                    us_read, us_write = await stack.enter_async_context(
                        connect_upstream(target_config.upstream, config.store_path,
                                       errlog=sys.stderr, server_id=name,
                                       callback_server=callback_server)
                    )
                    upstream_streams[name] = (us_read, us_write)
                elif name in marketplace_configs:
                    try:
                        upstream_cfg = _build_upstream_config(marketplace_configs[name])
                        us_read, us_write = await stack.enter_async_context(
                            connect_upstream(upstream_cfg, config.store_path,
                                           errlog=sys.stderr, server_id=name,
                                           callback_server=callback_server)
                        )
                        upstream_streams[name] = (us_read, us_write)
                    except Exception as exc:
                        logger.warning("Failed to connect marketplace server %s: %s", name, exc)
                        failed_targets.append(name)
                        # Deactivate in DB to prevent restart loops
                        try:
                            await store.deactivate_server(name)
                            logger.info("Deactivated server %s in database", name)
                        except Exception as deactivate_exc:
                            logger.error("Failed to deactivate server %s: %s", name, deactivate_exc)
            for name in failed_targets:
                del state.targets[name]

            with anyio.fail_after(SHUTDOWN_TIMEOUT):
                async with anyio.create_task_group() as tg:
                    manager = TargetManager(state, store, config.store_path,
                                           callback_server=callback_server)
                    manager.set_task_group(tg, shutdown_event)
                    state.target_manager = manager

                    async def _shutdown_on_signal():
                        with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                            async for sig in signals:
                                logger.info(f"Received {sig.name}, initiating graceful shutdown")
                                await _graceful_shutdown(
                                    state, shutdown_event, web_server, mcp_server,
                                    callback_web_server, tg, DRAIN_TIMEOUT, FLUSH_TIMEOUT
                                )
                                break

                    tg.start_soon(_shutdown_on_signal)

                    for name, target_state in state.targets.items():
                        us_read, us_write = upstream_streams[name]
                        tg.start_soon(run_proxy_for_target, target_state, us_read, us_write)
                        tg.start_soon(_flush_loop, target_state.engine, shutdown_event)

                    tg.start_soon(web_server.serve)
                    tg.start_soon(mcp_server.serve)
                    tg.start_soon(callback_web_server.serve)

    except Exception as exc:
        logger.exception(f"Error: {type(exc).__name__}: {exc}")

    await store.close()
    logger.info("Maskit stopped")


def main():
    try:
        anyio.run(async_main)
    except (KeyboardInterrupt, SystemExit):
        pass
    except BaseException as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
