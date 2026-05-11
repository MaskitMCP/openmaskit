"""Core proxy: bidirectional message relay with tool call interception."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest, JSONRPCResponse

if TYPE_CHECKING:
    from maskit.masking.engine import MaskingEngine
    from maskit.masking.store import MaskingStore

logger = logging.getLogger(__name__)


class ResponseDispatcher:
    """Routes proxy responses back to HTTP downstream waiters by request ID."""

    def __init__(self):
        self._waiters: dict[str | int, tuple[anyio.Event, list[SessionMessage]]] = {}

    def register(self, request_id: str | int) -> anyio.Event:
        event = anyio.Event()
        self._waiters[request_id] = (event, [])
        return event

    def dispatch(self, request_id: str | int, msg: SessionMessage) -> bool:
        if request_id in self._waiters:
            event, results = self._waiters[request_id]
            results.append(msg)
            event.set()
            return True
        return False

    def collect(self, request_id: str | int) -> SessionMessage | None:
        waiter = self._waiters.pop(request_id, None)
        if waiter:
            _, results = waiter
            return results[0] if results else None
        return None


@dataclass
class TargetState:
    """State for one upstream target."""

    name: str
    engine: MaskingEngine
    tool_schemas: list[dict[str, Any]] = field(default_factory=list)
    traffic_log: list[dict[str, Any]] = field(default_factory=list)
    response_dispatcher: ResponseDispatcher = field(default_factory=ResponseDispatcher)
    pending_tool_calls: dict[str | int, str] = field(default_factory=dict)
    pending_requests: dict[str | int, str] = field(default_factory=dict)
    initialized: bool = False
    init_result: dict[str, Any] | None = None
    ds_read_send: MemoryObjectSendStream[SessionMessage | Exception] | None = None
    ds_read_recv: MemoryObjectReceiveStream[SessionMessage | Exception] | None = None

    def cache_tool_schemas(self, schemas: list[dict[str, Any]]):
        self.tool_schemas = schemas

    def log_traffic(self, direction: str, method: str, data: dict[str, Any] | None = None):
        entry = {"direction": direction, "method": method, "data": data}
        self.traffic_log.append(entry)
        if len(self.traffic_log) > 1000:
            self.traffic_log = self.traffic_log[-500:]


class ProxyState:
    """Global state: registry of all targets."""

    def __init__(self):
        self.targets: dict[str, TargetState] = {}
        self.store: MaskingStore | None = None

    def get_target(self, name: str) -> TargetState | None:
        return self.targets.get(name)

    @property
    def target_names(self) -> list[str]:
        return list(self.targets.keys())


async def _fetch_tool_schemas(
    us_write: MemoryObjectSendStream[SessionMessage],
    target: TargetState,
):
    """Send a tools/list request upstream to populate the web UI."""
    tools_req = JSONRPCRequest(
        method="tools/list",
        id="__maskit_tools_list__",
        jsonrpc="2.0",
    )
    msg = SessionMessage(message=JSONRPCMessage(root=tools_req))
    await us_write.send(msg)
    logger.info("[%s] Sent tools/list request to upstream", target.name)


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
    try:
        logger.info("[%s] Bootstrapping upstream session...", target.name)
        with anyio.fail_after(30):
            await _bootstrap_upstream(us_read, us_write, target)
        logger.info("[%s] Bootstrap complete — %d tools cached", target.name, len(target.tool_schemas))
    except TimeoutError:
        logger.warning("[%s] Timed out bootstrapping upstream — tools will appear after first client connects", target.name)
    except Exception as exc:
        logger.error("[%s] Bootstrap failed: %s", target.name, exc, exc_info=True)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_relay_downstream_to_upstream, target, us_write)
        tg.start_soon(_relay_upstream_to_downstream, target, us_read, us_write)


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
            await us_write.send(modified)
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass


async def _relay_upstream_to_downstream(
    target: TargetState,
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
):
    """Relay messages from upstream (real MCP server) to downstream (HTTP clients)."""
    _needs_tools_fetch = False
    try:
        async for msg in us_read:
            if isinstance(msg, Exception):
                logger.warning("[%s] Upstream parse error: %s", target.name, msg)
                continue

            modified = _intercept_response(msg, target)
            if modified is not None:
                root = modified.message.root
                if isinstance(root, JSONRPCResponse) and root.id is not None:
                    if target.response_dispatcher.dispatch(root.id, modified):
                        continue

            if _needs_tools_fetch:
                _needs_tools_fetch = False
                await _fetch_tool_schemas(us_write, target)
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass


def _intercept_request(msg: SessionMessage, target: TargetState) -> SessionMessage:
    """Intercept downstream requests, unmask tool call arguments."""
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
        target.pending_tool_calls[root.id] = tool_name
        target.log_traffic("request", method, {"tool": tool_name})

        if target.engine:
            arguments = params.get("arguments")
            if arguments and isinstance(arguments, dict):
                unmasked = target.engine.unmask_arguments(tool_name, arguments)
                if unmasked != arguments:
                    masked_args = ", ".join(f"{v}" for v in arguments.values())
                    real_args = ", ".join(f"{v}" for v in unmasked.values())
                    logger.info("[%s] Received tool call: %s(%s)", target.name, tool_name, masked_args)
                    logger.info("[%s] Translating to:    %s(%s)", target.name, tool_name, real_args)
                params["arguments"] = unmasked

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
                target.log_traffic("response", "tools/list", {"count": len(tools)})
        return msg

    # Check if this is a response to a tools/call request
    if request_id in target.pending_tool_calls:
        tool_name = target.pending_tool_calls.pop(request_id)
        target.log_traffic("response", "tools/call", {"tool": tool_name})

        if target.engine and result:
            pending_before = len(target.engine._pending_writes)
            root.result = target.engine.mask_response(tool_name, result)
            new_masks = target.engine._pending_writes[pending_before:]
            for alias, real_value, _, field_path in new_masks:
                logger.info("[%s] Masked %s.%s: %s → %s", target.name, tool_name, field_path, real_value, alias)

    return msg
