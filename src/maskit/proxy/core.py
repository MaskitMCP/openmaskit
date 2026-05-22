"""Core proxy: bidirectional message relay with tool call interception."""

from __future__ import annotations

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import anyio
import httpx
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage
from mcp.types import (
    METHOD_NOT_FOUND,
    ErrorData,
    JSONRPCError,
    JSONRPCMessage,
    JSONRPCNotification,
    JSONRPCRequest,
    JSONRPCResponse,
)

if TYPE_CHECKING:
    from maskit.masking.engine import MaskingEngine
    from maskit.masking.store import MaskingStore

logger = logging.getLogger(__name__)

_MAX_PREVIEW_LEN = 1000  # Cap previews at 1000 chars to prevent memory bloat


def _truncate_preview(text: str | None) -> str | None:
    """Truncate preview text to prevent memory bloat."""
    if text is None:
        return None
    if len(text) <= _MAX_PREVIEW_LEN:
        return text
    return text[:_MAX_PREVIEW_LEN] + "... (truncated)"


class ResponseDispatcher:
    """Routes proxy responses back to HTTP downstream waiters by request ID."""

    _WAITER_TTL = 120.0
    _EVICTION_INTERVAL = 60.0  # Run cleanup every 60 seconds

    def __init__(self):
        self._waiters: dict[str | int, tuple[anyio.Event, list[SessionMessage], float]] = {}
        self._lock = anyio.Lock()
        self._shutdown_event: anyio.Event | None = None
        self._eviction_task: anyio.abc.CancelScope | None = None

    async def register(self, request_id: str | int) -> anyio.Event:
        async with self._lock:
            self._evict_stale()
            event = anyio.Event()
            self._waiters[request_id] = (event, [], time.time())
            return event

    async def dispatch(self, request_id: str | int, msg: SessionMessage) -> bool:
        async with self._lock:
            if request_id in self._waiters:
                event, results, _ = self._waiters[request_id]
                results.append(msg)
                event.set()
                return True
            return False

    def dispatch_sync(self, request_id: str | int, msg: SessionMessage) -> bool:
        """Synchronous dispatch for use in sync intercept functions."""
        if request_id in self._waiters:
            event, results, _ = self._waiters[request_id]
            results.append(msg)
            event.set()
            return True
        return False

    async def collect(self, request_id: str | int) -> SessionMessage | None:
        async with self._lock:
            waiter = self._waiters.pop(request_id, None)
            if waiter:
                _, results, _ = waiter
                return results[0] if results else None
            return None

    def _evict_stale(self):
        now = time.time()
        stale = [rid for rid, (_, _, ts) in self._waiters.items() if now - ts > self._WAITER_TTL]
        for rid in stale:
            self._waiters.pop(rid, None)
        if stale:
            logger.debug(f"Evicted {len(stale)} stale waiters from ResponseDispatcher")

    async def start_background_eviction(self, shutdown_event: anyio.Event):
        """Start background task to periodically evict stale waiters.

        This prevents memory leaks in long-running instances with infrequent requests.
        """
        self._shutdown_event = shutdown_event

        async def _eviction_loop():
            while not shutdown_event.is_set():
                await anyio.sleep(self._EVICTION_INTERVAL)
                async with self._lock:
                    self._evict_stale()

        # Run in background (caller should start this in task group)
        await _eviction_loop()

    def shutdown(self):
        """Signal all waiting clients that shutdown is in progress.

        All pending waiters receive a shutdown error immediately instead of
        waiting for their timeout.
        """
        # Wake all waiters - they can check if results are empty during shutdown
        for request_id, (event, results, _) in list(self._waiters.items()):
            # Just set the event without adding a message
            # The handler will detect empty results and return appropriate error
            event.set()

        # Clear all entries
        self._waiters.clear()


@dataclass
class TargetState:
    """State for one upstream target."""

    name: str
    engine: MaskingEngine
    tool_schemas: list[dict[str, Any]] = field(default_factory=list)
    hidden_tools: set[str] = field(default_factory=set)
    traffic_log: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=100))
    traffic_events: deque[dict[str, Any]] = field(default_factory=lambda: deque(maxlen=200))
    response_dispatcher: ResponseDispatcher = field(default_factory=ResponseDispatcher)
    pending_tool_calls: dict[str | int, dict[str, Any]] = field(default_factory=dict)
    pending_requests: dict[str | int, str] = field(default_factory=dict)
    initialized: bool = False
    init_result: dict[str, Any] | None = None
    ds_read_send: MemoryObjectSendStream[SessionMessage | Exception] | None = None
    ds_read_recv: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None
    needs_token_refresh: bool = False
    server_id: str | None = None

    def cache_tool_schemas(self, schemas: list[dict[str, Any]]):
        self.tool_schemas = schemas

    def log_traffic_entry(self, entry: dict[str, Any]):
        self.traffic_log.append(entry)
        self.traffic_events.append({"type": "new", "entry": entry})

    def update_traffic_entry(self, entry_id: str, updates: dict[str, Any]):
        for entry in reversed(self.traffic_log):
            if entry.get("id") == entry_id:
                entry.update(updates)
                break
        self.traffic_events.append({"type": "update", "id": entry_id, "updates": updates})


async def cleanup_target_state(target: TargetState) -> None:
    """Clean up target state during shutdown.

    - Notifies response waiters of shutdown
    - Clears pending tool calls
    - Closes downstream stream
    """
    # Notify HTTP waiters
    target.response_dispatcher.shutdown()

    # Clear pending state (helps with debugging/metrics)
    target.pending_tool_calls.clear()
    target.pending_requests.clear()

    # Close downstream stream
    if target.ds_read_send:
        await target.ds_read_send.aclose()


class ProxyState:
    """Global state: registry of all targets."""

    def __init__(self):
        self.targets: dict[str, TargetState] = {}
        self.store: MaskingStore | None = None
        self.target_manager: Any | None = None
        self.callback_server: Any | None = None
        self.config_target_ids: set[str] = set()
        self.mcp_port: int = 9474

    def get_target(self, name: str) -> TargetState | None:
        return self.targets.get(name)

    @property
    def target_names(self) -> list[str]:
        return list(self.targets.keys())


async def _bootstrap_upstream(
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
    target: TargetState,
):
    """Initialize the upstream session and fetch tool schemas proactively."""
    init_req = JSONRPCRequest(
        method="initialize",
        id="__maskit_init__",
        jsonrpc="2.0",
        params={
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "maskit", "version": "0.1.0"},
        },
    )
    logger.info("[%s] Sending initialize to upstream...", target.name)
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=init_req)))

    # Wait for initialize response
    async for response in us_read:
        if isinstance(response, Exception):
            logger.warning("[%s] Got exception during bootstrap init: %s", target.name, response)
            continue
        root = response.message.root
        if isinstance(root, JSONRPCResponse) and root.id == "__maskit_init__":
            target.init_result = root.result
            break
    else:
        logger.warning("[%s] Upstream stream closed before initialize response", target.name)
        return

    logger.info("[%s] Initialize response received", target.name)
    target.initialized = True

    # Send initialized notification
    notif = JSONRPCNotification(method="notifications/initialized", jsonrpc="2.0")
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=notif)))

    # Send tools/list
    tools_req = JSONRPCRequest(
        method="tools/list",
        id="__maskit_tools_list__",
        jsonrpc="2.0",
    )
    logger.info("[%s] Sending tools/list to upstream...", target.name)
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=tools_req)))

    # Wait for tools/list response
    async for response in us_read:
        if isinstance(response, Exception):
            logger.warning("[%s] Got exception during bootstrap tools/list: %s", target.name, response)
            continue
        root = response.message.root
        if isinstance(root, JSONRPCResponse) and root.id == "__maskit_tools_list__":
            result = root.result
            if result and "tools" in result:
                tools = result.get("tools", [])
                if tools and isinstance(tools, list):
                    target.cache_tool_schemas(tools)
                    logger.info("[%s] Cached %d tool schemas from upstream", target.name, len(tools))
            else:
                logger.warning("[%s] tools/list response had no tools: %s", target.name, result)
            break


async def run_proxy_for_target(
    target: TargetState,
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
):
    """Run the proxy relay for a single target."""
    if not target.initialized:
        try:
            logger.info("[%s] Bootstrapping upstream session...", target.name)
            with anyio.fail_after(30):
                await _bootstrap_upstream(us_read, us_write, target)
            logger.info("[%s] Bootstrap complete — %d tools cached", target.name, len(target.tool_schemas))
        except TimeoutError:
            logger.warning("[%s] Timed out bootstrapping upstream — tools will appear after first client connects", target.name)
        except Exception as exc:
            logger.error("[%s] Bootstrap failed: %s", target.name, exc, exc_info=True)

    try:
        async with anyio.create_task_group() as tg:
            tg.start_soon(_relay_downstream_to_upstream, target, us_write)
            tg.start_soon(_relay_upstream_to_downstream, target, us_read, us_write)
    except Exception as exc:
        # Catch any unhandled exceptions from relay tasks (e.g., OAuth 401 errors)
        logger.error(
            "[%s] Proxy relay crashed (possibly due to OAuth token expiration): %s",
            target.name, exc, exc_info=True
        )
        target.initialized = False
        raise  # Re-raise to let the manager handle cleanup


async def _relay_downstream_to_upstream(
    target: TargetState,
    us_write: MemoryObjectSendStream[SessionMessage],
):
    """Relay messages from downstream (HTTP clients) to upstream (real MCP server)."""
    try:
        async for msg in target.ds_read_recv:
            if isinstance(msg, Exception):
                logger.warning("[%s] Downstream parse error: %s", target.name, msg)
                continue

            modified = _intercept_request(msg, target)
            if modified is not None:
                await us_write.send(modified)
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401 and target.server_id:
            logger.warning(
                "[%s] OAuth 401 error, flagging for token refresh",
                target.name
            )
            target.needs_token_refresh = True
        else:
            logger.error("[%s] HTTP error %s: %s", target.name, e.response.status_code, e)
        target.initialized = False
    except Exception as e:
        # Catch any other exceptions (including network issues)
        logger.error(
            "[%s] Downstream relay error: %s",
            target.name, e
        )
        # Close the target gracefully
        target.initialized = False


async def _relay_upstream_to_downstream(
    target: TargetState,
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
):
    """Relay messages from upstream (real MCP server) to downstream (HTTP clients)."""
    try:
        async for msg in us_read:
            if isinstance(msg, Exception):
                logger.warning("[%s] Upstream parse error: %s", target.name, msg)
                continue

            modified = _intercept_response(msg, target)
            if modified is not None:
                root = modified.message.root
                if isinstance(root, JSONRPCResponse) and root.id is not None:
                    if await target.response_dispatcher.dispatch(root.id, modified):
                        continue
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 401 and target.server_id:
            logger.warning(
                "[%s] OAuth 401 error, flagging for token refresh",
                target.name
            )
            target.needs_token_refresh = True
        else:
            logger.error("[%s] HTTP error %s: %s", target.name, e.response.status_code, e)
        target.initialized = False
    except Exception as e:
        # Catch any other exceptions (including network issues)
        logger.error(
            "[%s] Upstream relay error: %s",
            target.name, e
        )
        # Close the target gracefully
        target.initialized = False


def _intercept_request(msg: SessionMessage, target: TargetState) -> SessionMessage | None:
    """Intercept downstream requests, unmask tool call arguments.

    Returns None if the message should not be forwarded upstream (e.g. blocked tool).
    """
    root = msg.message.root

    if not isinstance(root, JSONRPCRequest):
        return msg

    method = root.method
    params = root.params

    if method == "initialize" and root.id is not None:
        target.pending_requests[root.id] = "initialize"
    elif method == "tools/list" and root.id is not None:
        target.pending_requests[root.id] = "tools/list"
    elif method == "tools/call" and params:
        tool_name = params.get("name", "")

        if tool_name in target.hidden_tools:
            logger.info("[%s] Blocked call to hidden tool: %s", target.name, tool_name)
            target.log_traffic_entry({
                "id": str(time.time_ns()),
                "type": "blocked",
                "tool_name": tool_name,
                "timestamp": time.time(),
                "duration_ms": None,
                "status": "blocked",
                "masked_args": None,
                "unmasked_fields": [],
                "masked_response_fields": [],
                "response_preview": None,
                "reason": "hidden_tool",
            })
            error_response = SessionMessage(message=JSONRPCMessage(root=JSONRPCError(
                jsonrpc="2.0",
                id=root.id,
                error=ErrorData(code=METHOD_NOT_FOUND, message=f"Tool not found: {tool_name}"),
            )))
            target.response_dispatcher.dispatch_sync(root.id, error_response)
            return None

        request_ts = time.time()
        entry_id = str(time.time_ns())
        masked_args = None
        unmasked_fields = []

        if target.engine:
            arguments = params.get("arguments")
            if arguments and isinstance(arguments, dict):
                masked_args = dict(arguments)
                unmasked = target.engine.unmask_arguments(tool_name, arguments)
                if unmasked != arguments:
                    unmasked_fields = [k for k in arguments if arguments.get(k) != unmasked.get(k)]
                    masked_str = ", ".join(f"{v}" for v in arguments.values())
                    real_str = ", ".join(f"{v}" for v in unmasked.values())
                    logger.info("[%s] Received tool call: %s(%s)", target.name, tool_name, masked_str)
                    logger.info("[%s] Translating to:    %s(%s)", target.name, tool_name, real_str)
                params["arguments"] = unmasked

                violation = target.engine.check_guardrails(tool_name, params["arguments"])
                if violation:
                    logger.info("[%s] Guardrail blocked %s: %s", target.name, tool_name, violation)
                    target.log_traffic_entry({
                        "id": entry_id,
                        "type": "blocked",
                        "tool_name": tool_name,
                        "timestamp": request_ts,
                        "duration_ms": (time.time() - request_ts) * 1000,
                        "status": "blocked",
                        "masked_args": masked_args,
                        "unmasked_fields": unmasked_fields,
                        "masked_response_fields": [],
                        "response_preview": None,
                        "reason": violation,
                    })
                    error_response = SessionMessage(message=JSONRPCMessage(root=JSONRPCError(
                        jsonrpc="2.0",
                        id=root.id,
                        error=ErrorData(code=-32602, message=violation),
                    )))
                    target.response_dispatcher.dispatch_sync(root.id, error_response)
                    return None

                params["arguments"] = target.engine.apply_injections(tool_name, params["arguments"])

        target.pending_tool_calls[root.id] = {
            "tool_name": tool_name,
            "entry_id": entry_id,
            "timestamp": request_ts,
        }
        target.log_traffic_entry({
            "id": entry_id,
            "type": "tool_call",
            "tool_name": tool_name,
            "timestamp": request_ts,
            "duration_ms": None,
            "status": "pending",
            "masked_args": masked_args,
            "unmasked_fields": unmasked_fields,
            "masked_response_fields": [],
            "response_preview": None,
            "reason": None,
        })

    return msg


def _intercept_response(msg: SessionMessage, target: TargetState) -> SessionMessage | None:
    """Intercept upstream responses, mask tool call results and cache tool schemas.

    Returns None if the message should not be forwarded downstream.
    """
    root = msg.message.root

    if not isinstance(root, JSONRPCResponse):
        return msg

    request_id = root.id
    result = root.result

    # Response to our internal tools/list request — don't forward downstream
    if request_id == "__maskit_tools_list__":
        if result and "tools" in result:
            tools = result.get("tools", [])
            if tools and isinstance(tools, list):
                target.cache_tool_schemas(tools)
                logger.info("[%s] Cached %d tool schemas from upstream", target.name, len(tools))
        return None

    # Check if this is a response to a tracked request
    request_method = target.pending_requests.pop(request_id, None)

    if request_method == "initialize" and not target.initialized:
        target.initialized = True
        return msg

    if request_method == "tools/list":
        if result and "tools" in result:
            tools = result.get("tools", [])
            if tools and isinstance(tools, list):
                target.cache_tool_schemas(tools)
                if target.hidden_tools:
                    result["tools"] = [t for t in tools if t.get("name") not in target.hidden_tools]
                target.log_traffic_entry({
                    "id": str(time.time_ns()),
                    "type": "tools_list",
                    "tool_name": None,
                    "timestamp": time.time(),
                    "duration_ms": None,
                    "status": "complete",
                    "masked_args": None,
                    "unmasked_fields": [],
                    "masked_response_fields": [],
                    "response_preview": f"{len(result['tools'])} tools",
                    "reason": None,
                })
        return msg

    # Check if this is a response to a tools/call request
    if request_id in target.pending_tool_calls:
        pending = target.pending_tool_calls.pop(request_id)
        tool_name = pending["tool_name"]
        entry_id = pending["entry_id"]
        request_ts = pending["timestamp"]

        duration_ms = (time.time() - request_ts) * 1000
        masked_response_fields = []

        # Extract original response preview BEFORE masking
        original_preview = None
        if result and isinstance(result, dict):
            for block in result.get("content", []):
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                    original_preview = _truncate_preview(block["text"])
                    break

        if target.engine and result:
            pending_before = target.engine.pending_writes_count
            root.result = target.engine.mask_response(tool_name, result)
            new_masks = target.engine.get_new_masks_since(pending_before)
            masked_response_fields = [field_path for _, _, _, field_path in new_masks]
            for alias, real_value, _, field_path in new_masks:
                logger.info("[%s] Masked %s.%s: %s → %s", target.name, tool_name, field_path, real_value, alias)

        # Extract masked response preview (what the agent sees)
        masked_preview = None
        masked_result = root.result if root.result else result
        if masked_result and isinstance(masked_result, dict):
            for block in masked_result.get("content", []):
                if isinstance(block, dict) and block.get("type") == "text" and block.get("text"):
                    masked_preview = _truncate_preview(block["text"])
                    break

        target.update_traffic_entry(entry_id, {
            "status": "complete",
            "duration_ms": round(duration_ms, 1),
            "masked_response_fields": masked_response_fields,
            "response_preview": original_preview,
            "masked_preview": masked_preview,
        })

    return msg
