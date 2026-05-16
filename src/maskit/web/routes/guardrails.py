"""Argument guardrail CRUD routes."""

from __future__ import annotations

import re

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.rules import ArgumentGuardrail
from .mappers import _check_regex_safety

MAX_PATTERN_LENGTH = 500
MAX_MESSAGE_LENGTH = 500


async def guardrails_list(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    guardrails = [
        {
            "id": g.id,
            "tool_name": g.tool_name,
            "argument_name": g.argument_name,
            "match_type": g.match_type,
            "pattern": g.pattern,
            "message": g.message,
            "active": g.active,
        }
        for g in target.engine.guardrails
    ]
    return JSONResponse({"guardrails": guardrails})


async def guardrails_create(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "*")
    argument_name = body.get("argument_name", "*")
    match_type = body.get("match_type", "contains")
    pattern = body.get("pattern", "")
    message = body.get("message", "Blocked by guardrail")

    if not pattern:
        return JSONResponse({"error": "pattern is required"}, status_code=400)
    if match_type not in ("regex", "contains", "equals"):
        return JSONResponse({"error": "match_type must be 'regex', 'contains', or 'equals'"}, status_code=400)
    if len(pattern) > MAX_PATTERN_LENGTH:
        return JSONResponse({"error": f"pattern too long (max {MAX_PATTERN_LENGTH})"}, status_code=400)
    if len(message) > MAX_MESSAGE_LENGTH:
        return JSONResponse({"error": f"message too long (max {MAX_MESSAGE_LENGTH})"}, status_code=400)

    if match_type == "regex":
        # Safety check
        is_safe, error = _check_regex_safety(pattern)
        if not is_safe:
            return JSONResponse({"error": error}, status_code=400)

    guardrail = ArgumentGuardrail(
        tool_name=tool_name,
        argument_name=argument_name,
        match_type=match_type,
        pattern=pattern,
        message=message,
    )

    guardrail_id = await target.engine.store.add_guardrail(guardrail, target_name=target_name)
    guardrail.id = guardrail_id
    target.engine.add_guardrail(guardrail)

    return JSONResponse({
        "id": guardrail_id,
        "tool_name": guardrail.tool_name,
        "argument_name": guardrail.argument_name,
        "match_type": guardrail.match_type,
        "pattern": guardrail.pattern,
        "message": guardrail.message,
        "active": guardrail.active,
    }, status_code=201)


async def guardrails_update(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        guardrail_id = int(request.path_params["guardrail_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid guardrail_id"}, status_code=400)

    body = await request.json()

    if "match_type" in body and body["match_type"] not in ("regex", "contains", "equals"):
        return JSONResponse({"error": "match_type must be 'regex', 'contains', or 'equals'"}, status_code=400)

    # Get existing guardrail to check match_type
    guardrail = target.engine.get_guardrail(guardrail_id)
    if not guardrail:
        return JSONResponse({"error": "Guardrail not found"}, status_code=404)

    # Check if updating pattern with regex match_type
    current_match_type = body.get("match_type", guardrail.match_type)
    if "pattern" in body and current_match_type == "regex":
        # Safety check
        is_safe, error = _check_regex_safety(body["pattern"])
        if not is_safe:
            return JSONResponse({"error": error}, status_code=400)

    fields = {}
    for key in ("tool_name", "argument_name", "match_type", "pattern", "message", "active"):
        if key in body:
            fields[key] = body[key]

    if not fields:
        return JSONResponse({"error": "No fields to update"}, status_code=400)

    updated = await target.engine.store.update_guardrail(guardrail_id, **fields)
    if not updated:
        return JSONResponse({"error": "Guardrail not found"}, status_code=404)

    # Update in-memory state
    target.engine.remove_guardrail(guardrail_id)
    guardrails = await target.engine.store.get_guardrails(target_name=target_name)
    for g in guardrails:
        if g.id == guardrail_id:
            target.engine.add_guardrail(g)
            break

    return JSONResponse({"ok": True})


async def guardrails_delete(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        guardrail_id = int(request.path_params["guardrail_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid guardrail_id"}, status_code=400)

    deleted = await target.engine.store.delete_guardrail(guardrail_id)
    if deleted:
        target.engine.remove_guardrail(guardrail_id)
        return JSONResponse({"ok": True})
    return JSONResponse({"error": "Guardrail not found"}, status_code=404)
