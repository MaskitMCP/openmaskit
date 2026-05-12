"""Hidden tools API routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse


async def hidden_tools_list(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)
    return JSONResponse({"hidden_tools": list(target.hidden_tools)})


async def hidden_tools_toggle(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "")
    hidden = body.get("hidden", True)

    if not tool_name:
        return JSONResponse({"error": "tool_name is required"}, status_code=400)

    store = state.store
    if hidden:
        await store.hide_tool(tool_name, target_name=target_name)
        target.hidden_tools.add(tool_name)
    else:
        await store.unhide_tool(tool_name, target_name=target_name)
        target.hidden_tools.discard(tool_name)

    return JSONResponse({"ok": True, "hidden": hidden})
