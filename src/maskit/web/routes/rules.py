"""Masking rules CRUD routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.rules import MaskingRule

MAX_NAME_LENGTH = 256
MAX_PATH_LENGTH = 256
MAX_PREFIX_LENGTH = 64


async def rules_list(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    rules = [
        {
            "id": r.id,
            "tool_name": r.tool_name,
            "field_path": r.field_path,
            "alias_prefix": r.alias_prefix,
            "action": r.action,
            "active": r.active,
        }
        for r in target.engine.rules
    ]
    return JSONResponse({"rules": rules})


async def rules_create(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "*")
    field_path = body.get("field_path")
    alias_prefix = body.get("alias_prefix")

    if not field_path:
        return JSONResponse({"error": "field_path is required"}, status_code=400)
    if len(tool_name) > MAX_NAME_LENGTH:
        return JSONResponse({"error": f"tool_name too long (max {MAX_NAME_LENGTH})"}, status_code=400)
    if len(field_path) > MAX_PATH_LENGTH:
        return JSONResponse({"error": f"field_path too long (max {MAX_PATH_LENGTH})"}, status_code=400)
    if alias_prefix and len(alias_prefix) > MAX_PREFIX_LENGTH:
        return JSONResponse({"error": f"alias_prefix too long (max {MAX_PREFIX_LENGTH})"}, status_code=400)

    action = body.get("action", "mask")
    if action not in ("mask", "strip"):
        return JSONResponse({"error": "action must be 'mask' or 'strip'"}, status_code=400)

    rule = MaskingRule(
        tool_name=tool_name,
        field_path=field_path,
        alias_prefix=alias_prefix,
        action=action,
    )

    rule_id = await target.engine.store.add_rule(rule, target_name=target_name)
    rule.id = rule_id
    target.engine.add_rule(rule)

    return JSONResponse({
        "id": rule_id,
        "tool_name": rule.tool_name,
        "field_path": rule.field_path,
        "alias_prefix": rule.alias_prefix,
        "action": rule.action,
        "active": rule.active,
    }, status_code=201)


async def rules_update(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        rule_id = int(request.path_params["rule_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid rule_id"}, status_code=400)
    body = await request.json()
    alias_prefix = body.get("alias_prefix", "")

    updated = await target.engine.store.update_rule(rule_id, alias_prefix)
    if not updated:
        return JSONResponse({"error": "Rule not found"}, status_code=404)

    for r in target.engine.rules:
        if r.id == rule_id:
            r.alias_prefix = alias_prefix
            break

    return JSONResponse({"ok": True})


async def rules_delete(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    try:
        rule_id = int(request.path_params["rule_id"])
    except (ValueError, TypeError):
        return JSONResponse({"error": "Invalid rule_id"}, status_code=400)
    deleted = await target.engine.store.delete_rule(rule_id)

    if deleted:
        target.engine.remove_rule(rule_id)
        return JSONResponse({"ok": True})
    return JSONResponse({"error": "Rule not found"}, status_code=404)
