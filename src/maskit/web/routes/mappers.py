"""Response mapper API routes."""

from __future__ import annotations

import json
import re

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.mappers import ResponseMapper
from maskit.masking.parsing import try_parse_structured

MAX_PATTERN_LENGTH = 500
MAX_NAME_LENGTH = 256
MAX_PREFIX_LENGTH = 64

_REDOS_PATTERN = re.compile(r"(\(.+[+*]\))[+*]")


def _validate_dot_path(path: str) -> bool:
    if not path:
        return False
    parts = path.split(".")
    return all(part and part.replace("_", "").isalnum() for part in parts)


def _check_regex_safety(pattern: str) -> str | None:
    """Return an error message if the pattern looks unsafe, else None."""
    if len(pattern) > MAX_PATTERN_LENGTH:
        return f"Pattern too long (max {MAX_PATTERN_LENGTH} chars)"
    if _REDOS_PATTERN.search(pattern):
        return "Pattern contains nested quantifiers (potential ReDoS)"
    return None


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
                "config": m.config,
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
    mapper_type = body.get("mapper_type", "regex_replace")
    pattern = body.get("pattern", "")
    alias_prefix = body.get("alias_prefix", "")
    config = body.get("config")

    if len(tool_name) > MAX_NAME_LENGTH:
        return JSONResponse({"error": f"tool_name too long (max {MAX_NAME_LENGTH})"}, status_code=400)
    if len(alias_prefix) > MAX_PREFIX_LENGTH:
        return JSONResponse({"error": f"alias_prefix too long (max {MAX_PREFIX_LENGTH})"}, status_code=400)
    if not pattern:
        return JSONResponse({"error": "pattern is required"}, status_code=400)

    if mapper_type == "regex_replace":
        if not alias_prefix:
            return JSONResponse({"error": "alias_prefix is required"}, status_code=400)
        safety_err = _check_regex_safety(pattern)
        if safety_err:
            return JSONResponse({"error": safety_err}, status_code=400)
        try:
            re.compile(pattern)
        except re.error as exc:
            return JSONResponse({"error": f"Invalid regex: {exc}"}, status_code=400)
    elif mapper_type == "json_field_mask":
        if not alias_prefix:
            return JSONResponse({"error": "alias_prefix is required"}, status_code=400)
        if len(pattern) > MAX_PATTERN_LENGTH:
            return JSONResponse({"error": f"Pattern too long (max {MAX_PATTERN_LENGTH})"}, status_code=400)
        if not _validate_dot_path(pattern):
            return JSONResponse({"error": "Invalid dot-notation path"}, status_code=400)
    else:
        return JSONResponse({"error": f"Unknown mapper_type: {mapper_type}"}, status_code=400)

    mapper = ResponseMapper(
        tool_name=tool_name,
        mapper_type=mapper_type,
        pattern=pattern,
        alias_prefix=alias_prefix,
        config=config,
    )

    mapper_id = await target.engine.store.add_mapper(mapper, target_name=target_name)
    mapper.id = mapper_id
    target.engine.add_mapper(mapper)

    return JSONResponse(
        {
            "id": mapper.id,
            "tool_name": mapper.tool_name,
            "mapper_type": mapper.mapper_type,
            "pattern": mapper.pattern,
            "alias_prefix": mapper.alias_prefix,
            "order": mapper.order,
            "active": mapper.active,
            "config": mapper.config,
        },
        status_code=201,
    )


async def mappers_update(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        mapper_id = int(request.path_params["mapper_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid mapper_id"}, status_code=400)
    body = await request.json()
    pattern = body.get("pattern", "")
    alias_prefix = body.get("alias_prefix", "")

    if not pattern:
        return JSONResponse({"error": "pattern is required"}, status_code=400)
    if not alias_prefix:
        return JSONResponse({"error": "alias_prefix is required"}, status_code=400)
    if len(alias_prefix) > MAX_PREFIX_LENGTH:
        return JSONResponse({"error": f"alias_prefix too long (max {MAX_PREFIX_LENGTH})"}, status_code=400)

    mapper = target.engine.get_mapper(mapper_id)
    if mapper is None:
        return JSONResponse({"error": "Mapper not found"}, status_code=404)

    if mapper.mapper_type == "regex_replace":
        safety_err = _check_regex_safety(pattern)
        if safety_err:
            return JSONResponse({"error": safety_err}, status_code=400)
        try:
            re.compile(pattern)
        except re.error as exc:
            return JSONResponse({"error": f"Invalid regex: {exc}"}, status_code=400)
    elif mapper.mapper_type == "json_field_mask":
        if not _validate_dot_path(pattern):
            return JSONResponse({"error": "Invalid dot-notation path"}, status_code=400)

    updated = await target.engine.store.update_mapper(mapper_id, pattern, alias_prefix)
    if not updated:
        return JSONResponse({"error": "Mapper not found"}, status_code=404)

    target.engine.update_mapper_pattern(mapper_id, pattern, alias_prefix)

    return JSONResponse({"ok": True})


async def mappers_delete(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        mapper_id = int(request.path_params["mapper_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid mapper_id"}, status_code=400)
    deleted = await target.engine.store.delete_mapper(mapper_id)
    if not deleted:
        return JSONResponse({"error": "Mapper not found"}, status_code=404)

    target.engine.remove_mapper(mapper_id)

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

    await target.engine.store.reorder_mappers(mapper_ids)

    for idx, mid in enumerate(mapper_ids):
        for m in target.engine.mappers:
            if m.id == mid:
                m.order = idx
                break

    target.engine.mappers.sort(key=lambda m: m.order)
    return JSONResponse({"ok": True})


async def mappers_preview_json(request: Request):
    body = await request.json()
    text = body.get("text", "")
    path = body.get("path", "")
    alias_prefix = body.get("alias_prefix", "value")

    if not path:
        return JSONResponse({"error": "path is required"}, status_code=400)
    if not _validate_dot_path(path):
        return JSONResponse({"error": "Invalid dot-notation path"}, status_code=400)

    parse_result = try_parse_structured(text)
    if parse_result is None:
        return JSONResponse({"error": "Text is not valid JSON or Python repr"}, status_code=400)

    data = parse_result.data
    counter = [0]
    seen: dict[str, str] = {}
    matches: list[dict] = []

    def mask_value(value: str) -> str:
        if value not in seen:
            counter[0] += 1
            seen[value] = f"{alias_prefix}_{counter[0]}"
            matches.append({"original": value, "alias": seen[value]})
        return seen[value]

    def walk(data, path_parts: list[str]) -> bool:
        if not path_parts:
            return False

        if isinstance(data, list):
            any_masked = False
            for item in data:
                if walk(item, path_parts):
                    any_masked = True
            return any_masked

        if not isinstance(data, dict):
            return False

        key = path_parts[0]
        remaining = path_parts[1:]

        if key not in data:
            return False

        value = data[key]

        if not remaining:
            if isinstance(value, str):
                data[key] = mask_value(value)
                return True
            elif isinstance(value, (int, float, bool)):
                data[key] = mask_value(str(value))
                return True
            elif isinstance(value, list):
                any_masked = False
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        value[i] = mask_value(item)
                        any_masked = True
                return any_masked
            return False

        if isinstance(value, list):
            any_masked = False
            for item in value:
                if walk(item, remaining):
                    any_masked = True
            return any_masked
        elif isinstance(value, dict):
            return walk(value, remaining)
        return False

    walk(data, path.split("."))
    return JSONResponse({"result": json.dumps(data, indent=2), "matches": matches, "format": parse_result.format})


async def parse_text(request: Request):
    """Parse text as JSON or Python repr and return the structured data."""
    body = await request.json()
    text = body.get("text", "")

    if not text:
        return JSONResponse({"parsed": None, "format": None})

    result = try_parse_structured(text)
    if result is None:
        return JSONResponse({"parsed": None, "format": None})

    return JSONResponse({"parsed": result.data, "format": result.format})
