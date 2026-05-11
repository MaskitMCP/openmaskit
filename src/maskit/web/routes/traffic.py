"""Live traffic WebSocket and mappings API."""

from __future__ import annotations

import json

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect


async def api_mappings(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    mappings = await target.engine._store.get_all_mappings(target_name=target_name)
    return JSONResponse({"mappings": mappings})


async def TrafficWebSocket(websocket: WebSocket):
    await websocket.accept()
    state = websocket.app.state.proxy_state
    target_name = websocket.path_params["target_name"]
    target = state.get_target(target_name)

    if target is None:
        await websocket.close(code=4004)
        return

    last_idx = len(target.traffic_log)
    try:
        while True:
            await anyio.sleep(0.5)
            current = target.traffic_log[last_idx:]
            if current:
                for entry in current:
                    await websocket.send_text(json.dumps(entry))
                last_idx = len(target.traffic_log)
    except (WebSocketDisconnect, anyio.ClosedResourceError):
        pass
