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

            async with anyio.create_task_group() as tg:
                manager = TargetManager(state, store, config.store_path,
                                       callback_server=callback_server)
                manager.set_task_group(tg, shutdown_event)
                state.target_manager = manager

                async def _shutdown_on_signal():
                    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                        async for sig in signals:
                            logger.info(f"Shutting down (received {sig.name})")
                            shutdown_event.set()
                            web_server.should_exit = True
                            mcp_server.should_exit = True
                            callback_web_server.should_exit = True
                            for ts in state.targets.values():
                                if ts.ds_read_send:
                                    await ts.ds_read_send.aclose()
                            tg.cancel_scope.cancel()
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
