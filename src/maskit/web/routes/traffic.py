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

    mappings = await target.engine.store.get_all_mappings(target_name=target_name)
    return JSONResponse({"mappings": mappings})


async def TrafficWebSocket(websocket: WebSocket):
    await websocket.accept()
    state = websocket.app.state.proxy_state
    target_name = websocket.path_params["target_name"]
    target = state.get_target(target_name)

    if target is None:
        await websocket.close(code=4004)
        return

    # Send current entries as initial state
    for entry in target.traffic_log:
        await websocket.send_text(json.dumps({"type": "new", "entry": entry}))

    last_event_idx = len(target.traffic_events)
    try:
        while True:
            await anyio.sleep(0.5)
            current_len = len(target.traffic_events)
            if current_len > last_event_idx:
                new_count = current_len - last_event_idx
                new_events = list(target.traffic_events)[-new_count:]
                for event in new_events:
                    await websocket.send_text(json.dumps(event))
                last_event_idx = current_len
            elif current_len < last_event_idx:
                last_event_idx = current_len
    except (WebSocketDisconnect, anyio.ClosedResourceError):
        pass
