"""Core proxy: bidirectional message relay with tool call interception."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

import anyio
from anyio.streams.memory import MemoryObjectReceiveStream, MemoryObjectSendStream

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCNotification, JSONRPCRequest, JSONRPCResponse

if TYPE_CHECKING:
    from maskit.masking.engine import MaskingEngine

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


class ProxyState:
    """Shared state for the proxy, accessible by the Web UI."""

    def __init__(self, engine: MaskingEngine | None = None):
        self.engine = engine
        self.tool_schemas: list[dict[str, Any]] = []
        self.traffic_log: list[dict[str, Any]] = []
        self._pending_tool_calls: dict[str | int, str] = {}
        self._pending_requests: dict[str | int, str] = {}
        self._initialized: bool = False
        self._needs_tools_fetch: bool = False
        self._init_result: dict[str, Any] | None = None
        self.response_dispatcher: ResponseDispatcher = ResponseDispatcher()

    def cache_tool_schemas(self, schemas: list[dict[str, Any]]):
        self.tool_schemas = schemas

    def log_traffic(self, direction: str, method: str, data: dict[str, Any] | None = None):
        entry = {"direction": direction, "method": method, "data": data}
        self.traffic_log.append(entry)
        if len(self.traffic_log) > 1000:
            self.traffic_log = self.traffic_log[-500:]


async def _fetch_tool_schemas(
    us_write: MemoryObjectSendStream[SessionMessage],
    state: ProxyState,
):
    """Send a tools/list request upstream to populate the web UI."""
    tools_req = JSONRPCRequest(
        method="tools/list",
        id="__maskit_tools_list__",
        jsonrpc="2.0",
    )
    msg = SessionMessage(message=JSONRPCMessage(root=tools_req))
    await us_write.send(msg)
    logger.info("Sent tools/list request to upstream")


async def _bootstrap_upstream(
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
    state: ProxyState,
):
    """Initialize the upstream session and fetch tool schemas proactively."""
    # Send initialize
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
    logger.info("Sending initialize to upstream...")
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=init_req)))
    logger.info("Initialize sent, waiting for response...")

    # Wait for initialize response
    init_result = None
    async for response in us_read:
        if isinstance(response, Exception):
            logger.warning("Got exception during bootstrap init: %s", response)
            continue
        root = response.message.root
        if isinstance(root, JSONRPCResponse) and root.id == "__maskit_init__":
            init_result = root.result
            break
    else:
        logger.warning("Upstream stream closed before initialize response")
        return

    logger.info("Initialize response received")
    state._initialized = True
    state._init_result = init_result

    # Send initialized notification
    notif = JSONRPCNotification(method="notifications/initialized", jsonrpc="2.0")
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=notif)))

    # Send tools/list
    tools_req = JSONRPCRequest(
        method="tools/list",
        id="__maskit_tools_list__",
        jsonrpc="2.0",
    )
    logger.info("Sending tools/list to upstream...")
    await us_write.send(SessionMessage(message=JSONRPCMessage(root=tools_req)))

    # Wait for tools/list response
    async for response in us_read:
        if isinstance(response, Exception):
            logger.warning("Got exception during bootstrap tools/list: %s", response)
            continue
        root = response.message.root
        if isinstance(root, JSONRPCResponse) and root.id == "__maskit_tools_list__":
            result = root.result
            if result and "tools" in result:
                tools = result.get("tools", [])
                if tools and isinstance(tools, list):
                    state.cache_tool_schemas(tools)
                    logger.info("Cached %d tool schemas from upstream", len(tools))
            else:
                logger.warning("tools/list response had no tools: %s", result)
            break


async def run_proxy(
    ds_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    ds_write: MemoryObjectSendStream[SessionMessage],
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    us_write: MemoryObjectSendStream[SessionMessage],
    state: ProxyState,
):
    """Run the bidirectional proxy between downstream (AI host) and upstream (real server)."""
    # Bootstrap the upstream session so the web UI has tool schemas immediately
    try:
        logger.info("Bootstrapping upstream session...")
        with anyio.fail_after(30):
            await _bootstrap_upstream(us_read, us_write, state)
        logger.info("Bootstrap complete — %d tools cached", len(state.tool_schemas))
    except TimeoutError:
        logger.warning("Timed out bootstrapping upstream — tools will appear after first client connects")
    except Exception as exc:
        logger.error("Bootstrap failed: %s", exc, exc_info=True)

    async with anyio.create_task_group() as tg:
        tg.start_soon(_relay_downstream_to_upstream, ds_read, ds_write, us_write, state)
        tg.start_soon(_relay_upstream_to_downstream, us_read, ds_write, us_write, state)


async def _relay_downstream_to_upstream(
    ds_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    ds_write: MemoryObjectSendStream[SessionMessage],
    us_write: MemoryObjectSendStream[SessionMessage],
    state: ProxyState,
):
    """Relay messages from downstream (AI host) to upstream (real MCP server)."""
    try:
        async for msg in ds_read:
            if isinstance(msg, Exception):
                logger.warning("Downstream parse error: %s", msg)
                continue

            root = msg.message.root

            # If we already initialized upstream, synthesize the response for the host
            if (
                state._initialized
                and isinstance(root, JSONRPCRequest)
                and root.method == "initialize"
                and state._init_result is not None
            ):
                response = JSONRPCResponse(
                    id=root.id,
                    result=state._init_result,
                    jsonrpc="2.0",
                )
                await ds_write.send(
                    SessionMessage(message=JSONRPCMessage(root=response))
                )
                continue

            modified = _intercept_request(msg, state)
            await us_write.send(modified)
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass


async def _relay_upstream_to_downstream(
    us_read: MemoryObjectReceiveStream[SessionMessage | Exception],
    ds_write: MemoryObjectSendStream[SessionMessage],
    us_write: MemoryObjectSendStream[SessionMessage],
    state: ProxyState,
):
    """Relay messages from upstream (real MCP server) to downstream (AI host)."""
    try:
        async for msg in us_read:
            if isinstance(msg, Exception):
                logger.warning("Upstream parse error: %s", msg)
                continue

            modified = _intercept_response(msg, state)
            if modified is not None:
                root = modified.message.root
                if isinstance(root, JSONRPCResponse) and root.id is not None:
                    if state.response_dispatcher.dispatch(root.id, modified):
                        continue
                await ds_write.send(modified)

            if state._needs_tools_fetch:
                state._needs_tools_fetch = False
                await _fetch_tool_schemas(us_write, state)
    except (anyio.ClosedResourceError, anyio.EndOfStream):
        pass


def _intercept_request(msg: SessionMessage, state: ProxyState) -> SessionMessage:
    """Intercept downstream requests, unmask tool call arguments."""
    root = msg.message.root

    if not isinstance(root, JSONRPCRequest):
        return msg

    method = root.method
    params = root.params

    if method == "initialize" and root.id is not None:
        state._pending_requests[root.id] = "initialize"
    elif method == "tools/list" and root.id is not None:
        state._pending_requests[root.id] = "tools/list"
    elif method == "tools/call" and params:
        tool_name = params.get("name", "")
        state._pending_tool_calls[root.id] = tool_name
        state.log_traffic("request", method, {"tool": tool_name})

        if state.engine:
            arguments = params.get("arguments")
            if arguments and isinstance(arguments, dict):
                unmasked = state.engine.unmask_arguments(tool_name, arguments)
                if unmasked != arguments:
                    masked_args = ", ".join(f"{v}" for v in arguments.values())
                    real_args = ", ".join(f"{v}" for v in unmasked.values())
                    logger.info("Received tool call: %s(%s)", tool_name, masked_args)
                    logger.info("Translating to:    %s(%s)", tool_name, real_args)
                params["arguments"] = unmasked

    return msg


def _intercept_response(msg: SessionMessage, state: ProxyState) -> SessionMessage | None:
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
                state.cache_tool_schemas(tools)
                logger.info("Cached %d tool schemas from upstream", len(tools))
        return None

    # Check if this is a response to a tracked request
    request_method = state._pending_requests.pop(request_id, None)

    if request_method == "initialize" and not state._initialized:
        state._initialized = True
        if not state.tool_schemas:
            state._needs_tools_fetch = True
        return msg

    if request_method == "tools/list":
        if result and "tools" in result:
            tools = result.get("tools", [])
            if tools and isinstance(tools, list):
                state.cache_tool_schemas(tools)
                state.log_traffic("response", "tools/list", {"count": len(tools)})
        return msg

    # Check if this is a response to a tools/call request
    if request_id in state._pending_tool_calls:
        tool_name = state._pending_tool_calls.pop(request_id)
        state.log_traffic("response", "tools/call", {"tool": tool_name})

        if state.engine and result:
            pending_before = len(state.engine._pending_writes)
            root.result = state.engine.mask_response(tool_name, result)
            new_masks = state.engine._pending_writes[pending_before:]
            for alias, real_value, _, field_path in new_masks:
                logger.info("Masked %s.%s: %s → %s", tool_name, field_path, real_value, alias)

    return msg
