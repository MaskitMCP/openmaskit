"""HTTP MCP endpoint for downstream clients (e.g., Claude Code)."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import TYPE_CHECKING

import anyio
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest, JSONRPCResponse

from openmaskit.web.body_limit import (
    BodySizeLimitMiddleware,
    get_max_request_bytes,
)
from openmaskit.web.origin import OriginMiddleware, default_localhost_origins

if TYPE_CHECKING:
    from openmaskit.proxy.core import ProxyState

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

    # Check for batch requests (arrays) - not supported
    if isinstance(raw, list):
        return JSONResponse(
            {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Batch requests not supported"}, "id": None},
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

    # For requests that expect a response, register a waiter and forward.
    # The try/finally guarantees we always collect() (= pop the dict entry),
    # even if send() raises or the task is cancelled between register and
    # wait. Without it, the entry sits in _waiters until the 120s eviction
    # loop catches it.
    request_id = root.id
    event = await target.response_dispatcher.register(request_id)
    response_msg = None
    timed_out = False
    try:
        session_msg = SessionMessage(message=message)
        await target.ds_read_send.send(session_msg)

        try:
            with anyio.fail_after(60):
                await event.wait()
        except TimeoutError:
            timed_out = True
    finally:
        # Shield the cleanup so a parent-scope cancellation can't interrupt
        # collect() mid-pop and leave the waiter in the dict until eviction.
        with anyio.CancelScope(shield=True):
            response_msg = await target.response_dispatcher.collect(request_id)

    if timed_out:
        return JSONResponse(
            {
                "jsonrpc": "2.0",
                "error": {
                    "code": -32000,
                    "message": "Request timed out (server may be shutting down)",
                },
                "id": request_id,
            },
            status_code=504,
        )

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


def create_mcp_app(
    state: ProxyState,
    allowed_origins: Iterable[str] | None = None,
    max_request_bytes: int | None = None,
) -> Starlette:
    """Create the MCP HTTP endpoint app with path-based target routing.

    The endpoint is reachable from any webpage in the user's browser
    (``fetch('http://127.0.0.1:9474/...')``), so it gets the same Origin
    allow-list as the dashboard. Real MCP clients (Claude Code etc.) don't
    send an ``Origin`` header — those pass through unchanged.
    """
    routes = [
        Route("/{target_name}/mcp", _handle_mcp_post, methods=["POST"]),
        Route("/{target_name}/mcp", _handle_mcp_get, methods=["GET"]),
        Route("/{target_name}/mcp", _handle_mcp_delete, methods=["DELETE"]),
    ]

    if allowed_origins is None:
        web_port = getattr(state, "web_port", 9473)
        allowed_origins = default_localhost_origins(web_port)

    if max_request_bytes is None:
        max_request_bytes = get_max_request_bytes()

    middleware = [
        Middleware(BodySizeLimitMiddleware, max_bytes=max_request_bytes),
        Middleware(
            OriginMiddleware,
            allowed_origins=list(allowed_origins),
            protected_path_prefixes=("/",),
        ),
    ]

    app = Starlette(routes=routes, middleware=middleware)
    app.state.proxy_state = state
    return app
