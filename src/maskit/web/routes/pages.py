"""Page and tool schema routes."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import anyio
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

STATIC_DIR = Path(__file__).parent.parent / "static"


async def targets_page(request: Request):
    return FileResponse(STATIC_DIR / "targets.html")


async def tools_page(request: Request):
    return FileResponse(STATIC_DIR / "tools.html")


async def tool_detail_page(request: Request):
    return FileResponse(STATIC_DIR / "tool_detail.html")


async def api_targets(request: Request):
    state = request.app.state.proxy_state
    targets = []
    for name, ts in state.targets.items():
        targets.append({
            "name": name,
            "tool_count": len(ts.tool_schemas),
            "rule_count": len(ts.engine.rules),
            "mapper_count": len(ts.engine.mappers),
            "initialized": ts.initialized,
        })
    return JSONResponse({"targets": targets})


async def api_tools(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)
    return JSONResponse({
        "tools": target.tool_schemas,
        "hidden_tools": list(target.hidden_tools),
    })


async def api_tools_call(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

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

    event = target.response_dispatcher.register(request_id)
    await target.ds_read_send.send(session_msg)

    try:
        with anyio.fail_after(60):
            await event.wait()
    except TimeoutError:
        target.response_dispatcher.collect(request_id)
        return JSONResponse({"error": "Timeout waiting for response"}, status_code=504)

    response_msg = target.response_dispatcher.collect(request_id)
    if response_msg is None:
        return JSONResponse({"error": "No response received"}, status_code=500)

    root = response_msg.message.root
    if hasattr(root, "result"):
        alias_map = {alias: real for alias, real in target.engine._alias_cache.items()}
        return JSONResponse({"result": root.result, "aliases": alias_map})
    if hasattr(root, "error"):
        return JSONResponse({"error": root.error}, status_code=400)
    return JSONResponse({"error": "Unexpected response"}, status_code=500)
