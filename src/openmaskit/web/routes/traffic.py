"""Traffic audit log API: mappings + paginated traffic GET."""

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


_MAX_LIMIT = 200
_DEFAULT_LIMIT = 50


async def api_traffic(request: Request):
    """Return paginated traffic entries for a target.

    Query params:
      limit: int (1..200, default 50)
      before: int — cursor; return entries with id < before
    """
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    if state.traffic_store is None:
        return JSONResponse({"entries": [], "has_more": False})

    # Flush any buffered entries so we don't lie about "recent" traffic.
    if state.traffic_buffer is not None and state.traffic_buffer.has_pending:
        await state.traffic_buffer.flush(state.traffic_store)

    try:
        limit = int(request.query_params.get("limit", _DEFAULT_LIMIT))
    except ValueError:
        limit = _DEFAULT_LIMIT
    limit = max(1, min(limit, _MAX_LIMIT))

    before_raw = request.query_params.get("before")
    before_id: int | None = None
    if before_raw:
        try:
            before_id = int(before_raw)
        except ValueError:
            before_id = None

    # Fetch limit+1 to detect whether more pages exist without a second query.
    entries = await state.traffic_store.query(
        target_name, limit=limit + 1, before_id=before_id
    )
    has_more = len(entries) > limit
    entries = entries[:limit]

    return JSONResponse({
        "entries": [
            {
                "id": e.id,
                "ts": e.ts,
                "tool_name": e.tool_name,
                "request_id": e.request_id,
                "status": e.status,
                "duration_ms": e.duration_ms,
                "unmasked_args": e.unmasked_args,
                "unmasked_response": e.unmasked_response,
                "masked_args": e.masked_args,
                "masked_response": e.masked_response,
            }
            for e in entries
        ],
        "has_more": has_more,
    })
