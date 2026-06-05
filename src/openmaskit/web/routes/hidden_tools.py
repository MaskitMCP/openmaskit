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

    # When hiding, the supplied name must exact-match a tool the upstream
    # advertises. MCP tool names are case-sensitive identifiers, and the
    # runtime hidden-tool gate in proxy/core does a literal set lookup; if we
    # accepted, say, "FooBar" while the actual tool is "foobar", the user
    # would see a green confirmation while the dangerous tool stayed
    # callable. Unhiding is always allowed so a tool removed from the
    # upstream can still be cleaned out of the persisted set.
    if hidden:
        known_names = {t.get("name") for t in target.tool_schemas}
        if tool_name not in known_names:
            return JSONResponse(
                {
                    "error": "unknown_tool",
                    "message": (
                        f"Tool {tool_name!r} is not advertised by target "
                        f"{target_name!r}. Tool names are case-sensitive."
                    ),
                },
                status_code=400,
            )

    store = state.store
    if hidden:
        await store.hide_tool(tool_name, target_name=target_name)
        target.hidden_tools.add(tool_name)
    else:
        await store.unhide_tool(tool_name, target_name=target_name)
        target.hidden_tools.discard(tool_name)

    return JSONResponse({"ok": True, "hidden": hidden})
