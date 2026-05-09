"""Masking rules CRUD routes."""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse

from maskit.masking.rules import MaskingRule


async def rules_list(request: Request):
    state = request.app.state.proxy_state
    engine = state.engine
    if not engine:
        return JSONResponse({"rules": []})

    rules = [
        {
            "id": r.id,
            "tool_name": r.tool_name,
            "field_path": r.field_path,
            "alias_prefix": r.alias_prefix,
            "active": r.active,
        }
        for r in engine.rules
    ]
    return JSONResponse({"rules": rules})


async def rules_create(request: Request):
    state = request.app.state.proxy_state
    engine = state.engine
    if not engine:
        return JSONResponse({"error": "Engine not initialized"}, status_code=500)

    body = await request.json()
    tool_name = body.get("tool_name", "*")
    field_path = body.get("field_path")
    alias_prefix = body.get("alias_prefix")

    if not field_path:
        return JSONResponse({"error": "field_path is required"}, status_code=400)

    rule = MaskingRule(
        tool_name=tool_name,
        field_path=field_path,
        alias_prefix=alias_prefix,
    )

    rule_id = await engine._store.add_rule(rule)
    rule.id = rule_id
    engine.rules.append(rule)

    return JSONResponse({
        "id": rule_id,
        "tool_name": rule.tool_name,
        "field_path": rule.field_path,
        "alias_prefix": rule.alias_prefix,
        "active": rule.active,
    }, status_code=201)


async def rules_delete(request: Request):
    state = request.app.state.proxy_state
    engine = state.engine
    if not engine:
        return JSONResponse({"error": "Engine not initialized"}, status_code=500)

    rule_id = request.path_params["rule_id"]
    deleted = await engine._store.delete_rule(rule_id)

    if deleted:
        engine._rules = [r for r in engine._rules if r.id != rule_id]
        return JSONResponse({"ok": True})
    return JSONResponse({"error": "Rule not found"}, status_code=404)
