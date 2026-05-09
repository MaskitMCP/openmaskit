"""Live traffic WebSocket and mappings API."""

from __future__ import annotations

import json

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect


async def api_mappings(request: Request):
    state = request.app.state.proxy_state
    engine = state.engine
    if not engine:
        return JSONResponse({"mappings": []})

    mappings = await engine._store.get_all_mappings()
    return JSONResponse({"mappings": mappings})


async def TrafficWebSocket(websocket: WebSocket):
    await websocket.accept()
    state = websocket.app.state.proxy_state

    last_idx = len(state.traffic_log)
    try:
        while True:
            await anyio.sleep(0.5)
            current = state.traffic_log[last_idx:]
            if current:
                for entry in current:
                    await websocket.send_text(json.dumps(entry))
                last_idx = len(state.traffic_log)
    except (WebSocketDisconnect, anyio.ClosedResourceError):
        pass
