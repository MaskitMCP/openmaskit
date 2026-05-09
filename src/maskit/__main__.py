"""Maskit entry point."""

from __future__ import annotations

import logging
import os
import signal
import sys
from io import TextIOWrapper
from pathlib import Path

import anyio
import uvicorn
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage

from maskit.config import load_config
from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import ProxyState, run_proxy
from maskit.proxy.http_downstream import create_mcp_app
from maskit.proxy.upstream import connect_upstream
from maskit.web.app import create_app

logger = logging.getLogger(__name__)


async def _stdin_reader(
    send_stream: MemoryObjectSendStream[SessionMessage | Exception],
    shutdown_event: anyio.Event,
):
    stdin = anyio.wrap_file(
        TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    )
    try:
        async with send_stream:
            async for line in stdin:
                if shutdown_event.is_set():
                    break
                try:
                    message = JSONRPCMessage.model_validate_json(line)
                except Exception as exc:
                    await send_stream.send(exc)
                    continue
                await send_stream.send(SessionMessage(message))
    except (anyio.ClosedResourceError, anyio.EndOfStream, OSError):
        pass


async def _stdout_writer(
    recv_stream: MemoryObjectReceiveStream[SessionMessage],
):
    stdout = anyio.wrap_file(TextIOWrapper(sys.stdout.buffer, encoding="utf-8"))
    try:
        async with recv_stream:
            async for session_message in recv_stream:
                json_str = session_message.message.model_dump_json(
                    by_alias=True, exclude_none=True
                )
                await stdout.write(json_str + "\n")
                await stdout.flush()
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass


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

    rules = [
        MaskingRule(
            tool_name=r.tool_name,
            field_path=r.field_path,
            alias_prefix=r.alias_prefix,
        )
        for r in config.rules
    ]
    db_rules = await store.get_rules()
    rules.extend(db_rules)

    engine = MaskingEngine(rules, store)
    await engine.load_aliases()

    state = ProxyState(engine=engine)
    shutdown_event = anyio.Event()

    ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](32)
    ds_write_send, ds_write_recv = anyio.create_memory_object_stream[SessionMessage](32)

    print(f"Maskit proxy starting", file=sys.stderr)
    print(f"  Dashboard: http://127.0.0.1:{config.web_port}", file=sys.stderr)
    print(f"  MCP endpoint: http://127.0.0.1:{config.mcp_port}/mcp", file=sys.stderr)

    web_app = create_app(state, ds_read_send.clone())
    mcp_app = create_mcp_app(state, ds_read_send)

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
        async with connect_upstream(config, errlog=sys.stderr) as (us_read, us_write):
            async with anyio.create_task_group() as tg:

                async def _shutdown_on_signal():
                    with anyio.open_signal_receiver(signal.SIGINT, signal.SIGTERM) as signals:
                        async for sig in signals:
                            print(f"\nShutting down (received {sig.name})...", file=sys.stderr)
                            shutdown_event.set()
                            web_server.should_exit = True
                            mcp_server.should_exit = True
                            try:
                                os.close(sys.stdin.fileno())
                            except OSError:
                                pass
                            await ds_read_send.aclose()
                            await ds_write_send.aclose()
                            tg.cancel_scope.cancel()
                            break

                tg.start_soon(_shutdown_on_signal)
                tg.start_soon(_stdin_reader, ds_read_send.clone(), shutdown_event)
                tg.start_soon(_stdout_writer, ds_write_recv)
                tg.start_soon(_flush_loop, engine, shutdown_event)
                tg.start_soon(web_server.serve)
                tg.start_soon(mcp_server.serve)

                await run_proxy(ds_read_recv, ds_write_send, us_read, us_write, state)

                tg.cancel_scope.cancel()
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
