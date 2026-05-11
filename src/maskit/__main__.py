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
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import ProxyState, TargetState, run_proxy_for_target
from maskit.proxy.http_downstream import create_mcp_app
from maskit.proxy.upstream import connect_upstream
from maskit.web.app import create_app

logger = logging.getLogger(__name__)


async def _flush_loop(engine: MaskingEngine, shutdown_event: anyio.Event):
    """Periodically flush pending alias writes to the database."""
    while not shutdown_event.is_set():
        await anyio.sleep(1.0)
        if engine._pending_writes:
            await engine.flush_pending()
    # Final flush on shutdown
    if engine._pending_writes:
        await engine.flush_pending()


async def async_main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        stream=sys.stderr,
    )

    config_path = Path("maskit.yaml")
    if len(sys.argv) > 1:
        config_path = Path(sys.argv[1])

    config = load_config(config_path)

    store = await MaskingStore.create(config.store_path)

    state = ProxyState()
    state.store = store

    # Create per-target state
    for name, target_config in config.targets.items():
        rules = [
            MaskingRule(
                tool_name=r.tool_name,
                field_path=r.field_path,
                alias_prefix=r.alias_prefix,
            )
            for r in target_config.rules
        ]
        db_rules = await store.get_rules(target_name=name)
        rules.extend(db_rules)

        engine = MaskingEngine(rules, store, target_name=name)
        await engine.load_aliases()
        await engine.load_mappers()

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](32)

        target_state = TargetState(
            name=name,
            engine=engine,
            ds_read_send=ds_read_send,
            ds_read_recv=ds_read_recv,
        )
        state.targets[name] = target_state

    shutdown_event = anyio.Event()

    print("Maskit proxy starting", file=sys.stderr)
    print(f"  Dashboard: http://127.0.0.1:{config.web_port}", file=sys.stderr)
    print("  MCP endpoints:", file=sys.stderr)
    for name in state.target_names:
        print(f"    {name}: http://127.0.0.1:{config.mcp_port}/{name}/mcp", file=sys.stderr)

    web_app = create_app(state)
    mcp_app = create_mcp_app(state)

    uvicorn_config = uvicorn.Config(
        web_app,
        host="127.0.0.1",
        port=config.web_port,
        log_level="warning",
        log_config=None,
    )
    web_server = uvicorn.Server(uvicorn_config)
    web_server.install_signal_handlers = lambda: None

    mcp_uvicorn_config = uvicorn.Config(
        mcp_app,
        host="127.0.0.1",
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

            for name, target_state in state.targets.items():
                target_config = config.targets[name]
                us_read, us_write = await stack.enter_async_context(
                    connect_upstream(target_config.upstream, config.store_path, errlog=sys.stderr)
                )
                upstream_streams[name] = (us_read, us_write)

            async with anyio.create_task_group() as tg:

                async def _shutdown_on_signal():
                    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                        async for sig in signals:
                            print(f"\nShutting down (received {sig.name})...", file=sys.stderr)
                            shutdown_event.set()
                            web_server.should_exit = True
                            mcp_server.should_exit = True
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

    except Exception as exc:
        print(f"Error: {type(exc).__name__}: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)

    await store.close()
    print("Maskit stopped.", file=sys.stderr)


def main():
    try:
        anyio.run(async_main)
    except (KeyboardInterrupt, SystemExit):
        pass
    except BaseException as exc:
        print(f"Fatal error: {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        os._exit(1)
    finally:
        os._exit(0)


if __name__ == "__main__":
    main()
