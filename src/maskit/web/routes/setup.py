"""Setup and tool schema routes."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import anyio
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

STATIC_DIR = Path(__file__).parent.parent / "static"


async def index_page(request: Request):
    return FileResponse(STATIC_DIR / "index.html")


async def setup_page(request: Request):
    return FileResponse(STATIC_DIR / "setup.html")


async def api_tools(request: Request):
    state = request.app.state.proxy_state
    return JSONResponse({"tools": state.tool_schemas})


async def api_tools_call(request: Request):
    state = request.app.state.proxy_state
    ds_read_send = request.app.state.ds_read_send

    body = await request.json()
    tool_name = body.get("tool_name", "")
    arguments = body.get("arguments", {})

    if not tool_name:
        return JSONResponse({"error": "tool_name is required"}, status_code=400)

    request_id = f"__maskit_try_{uuid4().hex[:8]}__"

    rpc_request = JSONRPCRequest(
        method="tools/call",
        id=request_id,
        jsonrpc="2.0",
        params={"name": tool_name, "arguments": arguments},
    )
    session_msg = SessionMessage(message=JSONRPCMessage(root=rpc_request))

    event = state.response_dispatcher.register(request_id)
    await ds_read_send.send(session_msg)

    try:
        with anyio.fail_after(60):
            await event.wait()
    except TimeoutError:
        state.response_dispatcher.collect(request_id)
        return JSONResponse({"error": "Timeout waiting for response"}, status_code=504)

    response_msg = state.response_dispatcher.collect(request_id)
    if response_msg is None:
        return JSONResponse({"error": "No response received"}, status_code=500)

    root = response_msg.message.root
    if hasattr(root, "result"):
        return JSONResponse({"result": root.result})
    if hasattr(root, "error"):
        return JSONResponse({"error": root.error}, status_code=400)
    return JSONResponse({"error": "Unexpected response"}, status_code=500)
