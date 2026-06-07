"""Runtime target manager: hot-add and remove MCP server targets."""

from __future__ import annotations

import logging
import sys
from contextlib import AsyncExitStack
from typing import TYPE_CHECKING

import anyio
from anyio.streams.memory import MemoryObjectSendStream

from mcp.shared.message import SessionMessage

from openmaskit.container import stop_container
from openmaskit.masking.engine import MaskingEngine
from openmaskit.models import UpstreamHttpConfig, UpstreamStdioConfig
from openmaskit.proxy.core import TargetState, _bootstrap_upstream, run_proxy_for_target
from openmaskit.proxy.upstream import connect_upstream

if TYPE_CHECKING:
    from openmaskit.masking.store import MaskingStore
    from openmaskit.proxy.core import ProxyState

logger = logging.getLogger(__name__)


def _merge_user_args(base_args: list[str], config: dict) -> list[str]:
    """Merge base args with user-configured args from config.meta.user_args."""
    merged = base_args.copy()

    user_args = config.get("meta", {}).get("user_args", {})

    for arg_name, arg_config in user_args.items():
        values = arg_config.get("values", [])
        arg_format = arg_config.get("arg_format", "")

        if not arg_format:
            logger.warning(f"Missing arg_format for {arg_name}, skipping")
            continue

        for value in values:
            # Format: "--flag {value}" becomes ["--flag", "/path"]
            formatted = arg_format.replace("{value}", str(value))
            merged.extend(formatted.split())

    return merged


def _build_upstream_config(config: dict) -> UpstreamStdioConfig | UpstreamHttpConfig:
    transport = config.get("transport", "stdio")
    if transport == "stdio":
        base_args = config.get("args", [])
        merged_args = _merge_user_args(base_args, config)

        return UpstreamStdioConfig(
            command=config["command"],
            args=merged_args,
            env=config.get("env", {}),
        )
    else:
        oauth = config.get("oauth")
        return UpstreamHttpConfig(
            url=config["url"],
            oauth=oauth,
            headers=config.get("headers") or {},
        )


class TargetManager:
    """Manages hot-adding and removing MCP server targets at runtime."""

    def __init__(self, state: ProxyState, store: MaskingStore, store_path: str, container_runtime: str | None = None):
        self._state = state
        self._store = store
        self._store_path = store_path
        self._container_runtime = container_runtime
        self._exit_stacks: dict[str, AsyncExitStack] = {}
        self._task_group: anyio.abc.TaskGroup | None = None
        self._shutdown_event: anyio.Event | None = None

    def set_task_group(self, tg: anyio.abc.TaskGroup, shutdown_event: anyio.Event):
        self._task_group = tg
        self._shutdown_event = shutdown_event
        # Start refresh monitor only if we have a task group AND backend client
        # (backend_client is needed for token refresh, and is only set in production)
        if tg is not None and hasattr(self._state, 'backend_client'):
            tg.start_soon(self._monitor_token_refresh)

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
            server_id=server_id,  # Set server_id for OAuth refresh
            traffic_buffer=self._state.traffic_buffer,
        )

        stack = AsyncExitStack()
        await stack.__aenter__()

        try:
            upstream = _build_upstream_config(config)
            us_read, us_write, container_info = await stack.enter_async_context(
                connect_upstream(upstream, self._store_path, errlog=sys.stderr,
                               server_id=server_id,
                               container_runtime=self._container_runtime)
            )

            target.container_info = container_info
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
            # Wrap proxy task to handle failures gracefully
            async def run_proxy_with_error_handling():
                try:
                    await run_proxy_for_target(target, us_read, us_write)
                except Exception as exc:
                    logger.error(
                        "Target '%s' proxy crashed, disconnecting: %s",
                        server_id, exc, exc_info=True
                    )
                    # Auto-disconnect on crash
                    try:
                        await self.remove_target(server_id)
                    except Exception as cleanup_exc:
                        logger.error(
                            "Failed to cleanup crashed target '%s': %s",
                            server_id, cleanup_exc
                        )

            self._task_group.start_soon(run_proxy_with_error_handling)
            self._task_group.start_soon(self._flush_loop, engine)

        return target

    async def remove_target(self, server_id: str) -> None:
        """Teardown: close upstream connection, stop relay tasks, remove from state.

        Explicitly stops the upstream container before closing the exit stack.
        The stack-close path can fail (silently) when the stack is closed from
        a different task than the one that entered it — common in the
        deactivate/delete HTTP-handler path. Doing the stop here makes the
        cleanup independent of that close succeeding.
        """
        target = self._state.targets.get(server_id)

        # Explicit container stop, shielded so an outer cancellation can't
        # skip it. stop_container has its own internal timeout.
        if target is not None and target.container_info is not None:
            runtime, container_name = target.container_info
            with anyio.CancelScope(shield=True):
                await stop_container(runtime, container_name)

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

    async def _monitor_token_refresh(self) -> None:
        """Background task that monitors targets for refresh needs."""
        from openmaskit.proxy.upstream import refresh_backend_oauth_token

        # Use shorter sleep for tests
        check_interval = 0.1 if getattr(self, '_test_mode', False) else 5.0

        while self._shutdown_event and not self._shutdown_event.is_set():
            await anyio.sleep(check_interval)  # Will be cancelled by task group exit

            for server_id, target in list(self._state.targets.items()):
                if target.needs_token_refresh and target.server_id:
                    logger.info(f"Attempting automatic token refresh for {server_id}")

                    try:
                        # Get backend client from state
                        backend_client = getattr(self._state, 'backend_client', None)
                        if not backend_client:
                            logger.error("No backend client available for refresh")
                            target.needs_token_refresh = False
                            continue

                        # Call refresh
                        new_token = await refresh_backend_oauth_token(
                            target.server_id,
                            self._store_path,
                            backend_client,
                        )

                        if new_token:
                            # Success! Reconnect the target
                            logger.info(f"Token refreshed, reconnecting {server_id}")
                            record = await self._store.get_server(server_id)
                            config = record["config"] if record else None
                            if config is None:
                                logger.error(
                                    f"Cannot reconnect {server_id}: stored config is "
                                    f"undecryptable; uninstall and re-add the server."
                                )
                                return

                            # Remove old connection
                            await self.remove_target(server_id)

                            # Re-add with new token
                            await self.add_target(server_id, config)

                            logger.info(f"Successfully reconnected {server_id} with refreshed token")
                        else:
                            # Refresh failed - user must re-auth
                            logger.error(
                                f"Token refresh failed for {server_id} - user must re-authenticate"
                            )
                            target.needs_token_refresh = False  # Don't retry

                    except Exception as e:
                        logger.error(f"Error during token refresh for {server_id}: {e}")
                        target.needs_token_refresh = False
