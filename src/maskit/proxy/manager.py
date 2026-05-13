"""Runtime target manager: hot-add and remove MCP server targets."""

from __future__ import annotations

import logging
import sys
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING

import anyio
from anyio.streams.memory import MemoryObjectSendStream

from mcp.shared.message import SessionMessage

from maskit.masking.engine import MaskingEngine
from maskit.models import UpstreamHttpConfig, UpstreamStdioConfig
from maskit.proxy.core import TargetState, _bootstrap_upstream, run_proxy_for_target
from maskit.proxy.upstream import connect_upstream

if TYPE_CHECKING:
    from maskit.masking.store import MaskingStore
    from maskit.proxy.core import ProxyState

logger = logging.getLogger(__name__)


def _build_upstream_config(config: dict) -> UpstreamStdioConfig | UpstreamHttpConfig:
    transport = config.get("transport", "stdio")
    if transport == "stdio":
        return UpstreamStdioConfig(
            command=config["command"],
            args=config.get("args", []),
            env=config.get("env", {}),
        )
    else:
        oauth = config.get("oauth")
        return UpstreamHttpConfig(
            url=config["url"],
            oauth=oauth,
        )


class TargetManager:
    """Manages hot-adding and removing MCP server targets at runtime."""

    def __init__(self, state: ProxyState, store: MaskingStore, store_path: str, callback_server=None):
        self._state = state
        self._store = store
        self._store_path = store_path
        self._callback_server = callback_server
        self._exit_stacks: dict[str, AsyncExitStack] = {}
        self._task_group: anyio.abc.TaskGroup | None = None
        self._shutdown_event: anyio.Event | None = None

    def set_task_group(self, tg: anyio.abc.TaskGroup, shutdown_event: anyio.Event):
        self._task_group = tg
        self._shutdown_event = shutdown_event

    async def add_target(self, server_id: str, config: dict) -> TargetState:
        """Hot-add a new target: create state, connect upstream, start relay.

        Cleans up after itself on failure — callers should NOT call remove_target
        if this raises.
        """
        engine = MaskingEngine([], self._store, target_name=server_id)
        await engine.load_aliases()
        await engine.load_mappers()
        await engine.load_guardrails()
        await engine.load_injections()

        hidden = await self._store.get_hidden_tools(target_name=server_id)

        ds_read_send, ds_read_recv = anyio.create_memory_object_stream[SessionMessage | Exception](32)

        target = TargetState(
            name=server_id,
            engine=engine,
            hidden_tools=set(hidden),
            ds_read_send=ds_read_send,
            ds_read_recv=ds_read_recv,
        )

        stack = AsyncExitStack()
        await stack.__aenter__()

        try:
            upstream = _build_upstream_config(config)
            us_read, us_write = await stack.enter_async_context(
                connect_upstream(upstream, self._store_path, errlog=sys.stderr,
                               server_id=server_id, callback_server=self._callback_server)
            )

            self._exit_stacks[server_id] = stack
            self._state.targets[server_id] = target

            with anyio.fail_after(120):
                await _bootstrap_upstream(us_read, us_write, target)
        except BaseException:
            self._exit_stacks.pop(server_id, None)
            self._state.targets.pop(server_id, None)
            await stack.aclose()
            raise

        if self._task_group:
            self._task_group.start_soon(run_proxy_for_target, target, us_read, us_write)
            self._task_group.start_soon(self._flush_loop, engine)

        return target

    async def remove_target(self, server_id: str) -> None:
        """Teardown: close upstream connection, stop relay tasks, remove from state."""
        target = self._state.targets.get(server_id)
        if target and target.ds_read_send:
            try:
                await target.ds_read_send.aclose()
            except (anyio.ClosedResourceError, anyio.EndOfStream):
                pass

        stack = self._exit_stacks.pop(server_id, None)
        if stack:
            try:
                await stack.aclose()
            except Exception as exc:
                logger.warning("Error closing exit stack for %s: %s", server_id, exc)

        self._state.targets.pop(server_id, None)

    async def _flush_loop(self, engine: MaskingEngine) -> None:
        while self._shutdown_event and not self._shutdown_event.is_set():
            await anyio.sleep(1.0)
            if engine.has_pending_writes:
                try:
                    await engine.flush_pending()
                except Exception:
                    logger.exception("Failed to flush aliases for hot-added target")
        if engine.has_pending_writes:
            try:
                await engine.flush_pending()
            except Exception:
                logger.exception("Failed final flush for hot-added target")
