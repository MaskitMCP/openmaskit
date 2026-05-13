"""Argument injection CRUD routes."""

from __future__ import annotations

import json

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.rules import ArgumentInjection


async def injections_list(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    injections = [
        {
            "id": i.id,
            "tool_name": i.tool_name,
            "argument_name": i.argument_name,
            "value": i.value,
            "mode": i.mode,
            "active": i.active,
        }
        for i in target.engine.injections
    ]
    return JSONResponse({"injections": injections})


async def injections_create(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "*")
    argument_name = body.get("argument_name", "")
    value = body.get("value", "")
    mode = body.get("mode", "set")

    if not argument_name:
        return JSONResponse({"error": "argument_name is required"}, status_code=400)
    if not value:
        return JSONResponse({"error": "value is required"}, status_code=400)
    if mode not in ("set", "default", "append"):
        return JSONResponse({"error": "mode must be 'set', 'default', or 'append'"}, status_code=400)

    try:
        json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return JSONResponse({"error": "value must be valid JSON"}, status_code=400)

    injection = ArgumentInjection(
        tool_name=tool_name,
        argument_name=argument_name,
        value=value,
        mode=mode,
    )

    injection_id = await target.engine.store.add_injection(injection, target_name=target_name)
    injection.id = injection_id
    target.engine.add_injection(injection)

    return JSONResponse({
        "id": injection_id,
        "tool_name": injection.tool_name,
        "argument_name": injection.argument_name,
        "value": injection.value,
        "mode": injection.mode,
        "active": injection.active,
    }, status_code=201)


async def injections_update(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        injection_id = int(request.path_params["injection_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid injection_id"}, status_code=400)

    body = await request.json()

    if "mode" in body and body["mode"] not in ("set", "default", "append"):
        return JSONResponse({"error": "mode must be 'set', 'default', or 'append'"}, status_code=400)

    if "value" in body:
        try:
            json.loads(body["value"])
        except (json.JSONDecodeError, TypeError):
            return JSONResponse({"error": "value must be valid JSON"}, status_code=400)

    fields = {}
    for key in ("tool_name", "argument_name", "value", "mode", "active"):
        if key in body:
            fields[key] = body[key]

    if not fields:
        return JSONResponse({"error": "No fields to update"}, status_code=400)

    updated = await target.engine.store.update_injection(injection_id, **fields)
    if not updated:
        return JSONResponse({"error": "Injection not found"}, status_code=404)

    # Update in-memory state
    target.engine.remove_injection(injection_id)
    injections = await target.engine.store.get_injections(target_name=target_name)
    for i in injections:
        if i.id == injection_id:
            target.engine.add_injection(i)
            break

    return JSONResponse({"ok": True})


async def injections_delete(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        injection_id = int(request.path_params["injection_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid injection_id"}, status_code=400)

    deleted = await target.engine.store.delete_injection(injection_id)
    if deleted:
        target.engine.remove_injection(injection_id)
        return JSONResponse({"ok": True})
    return JSONResponse({"error": "Injection not found"}, status_code=404)
