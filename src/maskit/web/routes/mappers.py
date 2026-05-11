"""Response mapper API routes."""

from __future__ import annotations

import re

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.mappers import ResponseMapper


async def mappers_list(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    tool_name = request.query_params.get("tool_name")
    mappers = target.engine.mappers
    if tool_name:
        mappers = [m for m in mappers if m.matches_tool(tool_name)]

    return JSONResponse({
        "mappers": [
            {
                "id": m.id,
                "tool_name": m.tool_name,
                "mapper_type": m.mapper_type,
                "pattern": m.pattern,
                "alias_prefix": m.alias_prefix,
                "order": m.order,
                "active": m.active,
            }
            for m in mappers
        ]
    })


async def mappers_create(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "*")
    pattern = body.get("pattern", "")
    alias_prefix = body.get("alias_prefix", "")

    if not pattern:
        return JSONResponse({"error": "pattern is required"}, status_code=400)
    if not alias_prefix:
        return JSONResponse({"error": "alias_prefix is required"}, status_code=400)

    try:
        re.compile(pattern)
    except re.error as exc:
        return JSONResponse({"error": f"Invalid regex: {exc}"}, status_code=400)

    mapper = ResponseMapper(
        tool_name=tool_name,
        mapper_type="regex_replace",
        pattern=pattern,
        alias_prefix=alias_prefix,
    )

    mapper_id = await target.engine._store.add_mapper(mapper, target_name=target_name)
    mapper.id = mapper_id

    target.engine._mappers.append(mapper)
    target.engine._compiled_patterns[mapper_id] = re.compile(pattern)

    return JSONResponse(
        {
            "id": mapper.id,
            "tool_name": mapper.tool_name,
            "mapper_type": mapper.mapper_type,
            "pattern": mapper.pattern,
            "alias_prefix": mapper.alias_prefix,
            "order": mapper.order,
            "active": mapper.active,
        },
        status_code=201,
    )


async def mappers_delete(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    mapper_id = int(request.path_params["mapper_id"])
    deleted = await target.engine._store.delete_mapper(mapper_id)
    if not deleted:
        return JSONResponse({"error": "Mapper not found"}, status_code=404)

    target.engine._mappers = [m for m in target.engine._mappers if m.id != mapper_id]
    target.engine._compiled_patterns.pop(mapper_id, None)

    return JSONResponse({"ok": True})


async def mappers_preview(request: Request):
    body = await request.json()
    text = body.get("text", "")
    pattern = body.get("pattern", "")
    alias_prefix = body.get("alias_prefix", "value")

    if not pattern:
        return JSONResponse({"error": "pattern is required"}, status_code=400)

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        return JSONResponse({"error": f"Invalid regex: {exc}"}, status_code=400)

    counter = 0
    seen: dict[str, str] = {}
    matches: list[dict] = []

    def replacer(match: re.Match) -> str:
        nonlocal counter
        if match.lastindex and match.lastindex >= 1:
            captured = match.group(1)
            if captured not in seen:
                counter += 1
                seen[captured] = f"{alias_prefix}_{counter}"
            alias = seen[captured]
            start, end = match.span(1)
            full_start, _ = match.span(0)
            matches.append({"original": captured, "alias": alias})
            return match.group(0)[: start - full_start] + alias + match.group(0)[end - full_start :]
        else:
            full = match.group(0)
            if full not in seen:
                counter += 1
                seen[full] = f"{alias_prefix}_{counter}"
            alias = seen[full]
            matches.append({"original": full, "alias": alias})
            return alias

    result = compiled.sub(replacer, text)
    return JSONResponse({"result": result, "matches": matches})


async def mappers_reorder(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    mapper_ids = body.get("mapper_ids", [])
    if not mapper_ids:
        return JSONResponse({"error": "mapper_ids is required"}, status_code=400)

    await target.engine._store.reorder_mappers(mapper_ids)

    for idx, mid in enumerate(mapper_ids):
        for m in target.engine._mappers:
            if m.id == mid:
                m.order = idx
                break

    target.engine._mappers.sort(key=lambda m: m.order)
    return JSONResponse({"ok": True})
