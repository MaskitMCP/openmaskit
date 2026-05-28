"""Mappings API. (The lazy traffic GET endpoint is added in a follow-up PR.)"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse


async def api_mappings(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    mappings = await target.engine.store.get_all_mappings(target_name=target_name)
    return JSONResponse({"mappings": mappings})
