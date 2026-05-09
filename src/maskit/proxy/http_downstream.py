"""HTTP MCP endpoint for downstream clients (e.g., Claude Code)."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

if TYPE_CHECKING:
    from anyio.streams.memory import MemoryObjectSendStream

    from maskit.proxy.core import ProxyState

logger = logging.getLogger(__name__)


async def _handle_mcp_post(request: Request) -> Response:
    """Handle POST /mcp — incoming JSON-RPC from the MCP client."""
    state: ProxyState = request.app.state.proxy_state
    ds_read_send: MemoryObjectSendStream = request.app.state.ds_read_send

    body = await request.body()
    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
            status_code=400,
        )

    # Parse as JSON-RPC message
    try:
        message = JSONRPCMessage.model_validate(raw)
    except Exception:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": raw.get("id")},
            status_code=400,
        )

    root = message.root

    # Handle initialize locally
    if isinstance(root, JSONRPCRequest) and root.method == "initialize":
        if state._init_result:
            resp = {"jsonrpc": "2.0", "id": root.id, "result": state._init_result}
            return JSONResponse(resp)
        # Not yet initialized upstream — shouldn't happen but handle gracefully
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Server not ready"}, "id": root.id},
            status_code=503,
        )

    # Handle notifications (no response expected)
    if not isinstance(root, JSONRPCRequest) or root.id is None:
        # Notifications like notifications/initialized — just acknowledge
        return Response(status_code=202)

    # For requests that expect a response, register a waiter and forward
    request_id = root.id
    event = state.response_dispatcher.register(request_id)

    session_msg = SessionMessage(message=message)
    await ds_read_send.send(session_msg)

    # Wait for the response from the proxy relay
    with anyio.fail_after(60):
        await event.wait()

    response_msg = state.response_dispatcher.collect(request_id)
    if response_msg is None:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32603, "message": "No response"}, "id": request_id},
            status_code=500,
        )

    resp_json = json.loads(
        response_msg.message.model_dump_json(by_alias=True, exclude_none=True)
    )
    return JSONResponse(resp_json)


async def _handle_mcp_get(request: Request) -> Response:
    """Handle GET /mcp — SSE stream for server notifications (not needed for basic proxy)."""
    return Response(status_code=405)


async def _handle_mcp_delete(request: Request) -> Response:
    """Handle DELETE /mcp — session termination (no-op for proxy)."""
    return Response(status_code=200)


def create_mcp_app(state: ProxyState, ds_read_send: MemoryObjectSendStream) -> Starlette:
    """Create the MCP HTTP endpoint app."""
    routes = [
        Route("/mcp", _handle_mcp_post, methods=["POST"]),
        Route("/mcp", _handle_mcp_get, methods=["GET"]),
        Route("/mcp", _handle_mcp_delete, methods=["DELETE"]),
    ]
    app = Starlette(routes=routes)
    app.state.proxy_state = state
    app.state.ds_read_send = ds_read_send
    return app
