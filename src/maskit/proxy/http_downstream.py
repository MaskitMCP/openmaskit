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
    from maskit.proxy.core import ProxyState

logger = logging.getLogger(__name__)


async def _handle_mcp_post(request: Request) -> Response:
    """Handle POST /{target_name}/mcp — incoming JSON-RPC from the MCP client."""
    target_name = request.path_params["target_name"]
    state: ProxyState = request.app.state.proxy_state
    target = state.get_target(target_name)

    if target is None:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32600, "message": f"Unknown target: {target_name}"}, "id": None},
            status_code=404,
        )

    body = await request.body()
    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
            status_code=400,
        )

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
        if target.init_result:
            resp = {"jsonrpc": "2.0", "id": root.id, "result": target.init_result}
            return JSONResponse(resp)
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Server not ready"}, "id": root.id},
            status_code=503,
        )

    # Handle notifications (no response expected)
    if not isinstance(root, JSONRPCRequest) or root.id is None:
        return Response(status_code=202)

    # For requests that expect a response, register a waiter and forward
    request_id = root.id
    event = target.response_dispatcher.register(request_id)

    session_msg = SessionMessage(message=message)
    await target.ds_read_send.send(session_msg)

    # Wait for the response from the proxy relay
    try:
        with anyio.fail_after(60):
            await event.wait()
    except TimeoutError:
        target.response_dispatcher.collect(request_id)
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32603, "message": "Upstream timeout"}, "id": request_id},
            status_code=504,
        )

    response_msg = target.response_dispatcher.collect(request_id)
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
    """Handle GET /{target_name}/mcp — SSE stream (not needed for basic proxy)."""
    return Response(status_code=405)


async def _handle_mcp_delete(request: Request) -> Response:
    """Handle DELETE /{target_name}/mcp — session termination (no-op for proxy)."""
    return Response(status_code=200)


def create_mcp_app(state: ProxyState) -> Starlette:
    """Create the MCP HTTP endpoint app with path-based target routing."""
    routes = [
        Route("/{target_name}/mcp", _handle_mcp_post, methods=["POST"]),
        Route("/{target_name}/mcp", _handle_mcp_get, methods=["GET"]),
        Route("/{target_name}/mcp", _handle_mcp_delete, methods=["DELETE"]),
    ]
    app = Starlette(routes=routes)
    app.state.proxy_state = state
    return app
