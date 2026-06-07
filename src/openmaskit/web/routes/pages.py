"""Page and tool schema routes."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import anyio
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage, JSONRPCRequest

from openmaskit import __version__
from openmaskit.config_serde import load_display_config

import logging

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent.parent / "static"


async def targets_page(request: Request):
    return FileResponse(STATIC_DIR / "targets.html")


async def tools_page(request: Request):
    return FileResponse(STATIC_DIR / "tools.html")


async def tool_detail_page(request: Request):
    return FileResponse(STATIC_DIR / "tool_detail.html")


async def api_csrf(request: Request):
    """Return the per-process CSRF token to the dashboard JS.

    Gated by ``OriginMiddleware``: a malicious page in the user's browser can
    only fetch this endpoint cross-origin if its ``Origin`` is in the dashboard
    allow-list, which by construction it isn't. CLI / curl callers can read it
    too — that's fine, they're already same-machine.
    """
    token = getattr(request.app.state, "csrf_token", None)
    if not token:
        return JSONResponse({"error": "csrf_unavailable"}, status_code=500)
    return JSONResponse({"token": token})


async def api_config(request: Request):
    state = request.app.state.proxy_state
    vs = state.version_status or {}
    return JSONResponse({
        "mcp_port": state.mcp_port,
        "current_version": __version__,
        "version_status": {
            "supported": vs.get("supported", True),
            "update_required": vs.get("update_required", False),
            "update_available": vs.get("update_available", False),
            "latest_version": vs.get("latest_version"),
        },
    })


def _display_config_for_record(record: dict | None) -> dict | None:
    """Best-effort redacted display config for an mcp_servers row."""
    if not record:
        return None
    try:
        return load_display_config(record["config_json"])
    except Exception:
        logger.warning(
            "Failed to parse config_json for %r; returning null config",
            record.get("id"),
            exc_info=True,
        )
        return None


def _editable(name: str, record: dict | None, state) -> bool:
    """A row is editable through the custom-target API only when it's not from
    the config file AND was added as a custom target. Marketplace rows live on
    their own (Marketplace tab) lifecycle; editing them through the dashboard
    Edit modal would break their relationship with the catalog entry.
    """
    if name in state.config_target_ids:
        return False
    if record is None:
        return False  # config-file-only target or unknown — not editable
    return record.get("source") == "custom"


async def api_targets(request: Request):
    state = request.app.state.proxy_state
    store = state.store

    # Get all servers from database (marketplace and custom)
    db_servers = await store.get_all_servers()
    db_servers_map = {s["id"]: s for s in db_servers}

    targets = []
    seen_ids = set()

    # First, add all currently connected servers (from state.targets)
    for name, ts in state.targets.items():
        seen_ids.add(name)
        server_record = db_servers_map.get(name)

        targets.append({
            "name": name,
            "display_name": server_record["name"] if server_record else name,
            "icon_url": server_record.get("icon_url") if server_record else None,
            "active": True,  # If it's in state.targets, it's active
            "initialized": ts.initialized,
            "tool_count": len(ts.tool_schemas),
            "rule_count": len(ts.engine.rules),
            "mapper_count": len(ts.engine.mappers),
            "editable": _editable(name, server_record, state),
            "source": server_record["source"] if server_record else "config",
            "backend_id": server_record.get("backend_id") if server_record else None,
            "config": _display_config_for_record(server_record),
        })

    # Then, add inactive servers from database that aren't in state.targets.
    # We include any row not in state.targets, even if the DB still marks it
    # active — a row that's "active in DB but not connected" is an orphan
    # (failed startup reconnect, malformed config, etc.) and the user needs
    # to see it to act on it.
    for server in db_servers:
        if server["id"] not in seen_ids:
            targets.append({
                "name": server["id"],
                "display_name": server["name"],
                "icon_url": server.get("icon_url"),
                "active": False,
                "initialized": False,
                "tool_count": 0,
                "rule_count": 0,
                "mapper_count": 0,
                "editable": _editable(server["id"], server, state),
                "source": server["source"],
                "backend_id": server.get("backend_id"),
                "config": _display_config_for_record(server),
            })

    return JSONResponse({"targets": targets})


async def api_tools(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)
    include_hidden = request.query_params.get("include_hidden") == "1"
    response = {"tools": target.tool_schemas}
    if include_hidden:
        response["hidden_tools"] = list(target.hidden_tools)
    return JSONResponse(response)


async def api_tools_call(request: Request):
    state = request.app.state.proxy_state
    target_name = request.path_params["target_name"]
    target = state.get_target(target_name)
    if target is None:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    tool_name = body.get("tool_name", "")
    arguments = body.get("arguments", {})

    if not tool_name:
        return JSONResponse({"error": "tool_name is required"}, status_code=400)

    request_id = f"__openmaskit_try_{uuid4().hex[:8]}__"

    rpc_request = JSONRPCRequest(
        method="tools/call",
        id=request_id,
        jsonrpc="2.0",
        params={"name": tool_name, "arguments": arguments},
    )
    session_msg = SessionMessage(message=JSONRPCMessage(root=rpc_request))

    # try/finally guarantees collect() runs even if send() raises or the
    # task is cancelled — otherwise the waiter sits in _waiters until the
    # background eviction loop catches it.
    event = await target.response_dispatcher.register(request_id)
    response_msg = None
    timed_out = False
    try:
        await target.ds_read_send.send(session_msg)
        try:
            with anyio.fail_after(60):
                await event.wait()
        except TimeoutError:
            timed_out = True
    finally:
        # Shield the cleanup so parent-scope cancellation can't interrupt
        # collect() and leave the waiter dangling.
        with anyio.CancelScope(shield=True):
            response_msg = await target.response_dispatcher.collect(request_id)

    if timed_out:
        return JSONResponse({"error": "Timeout waiting for response"}, status_code=504)
    if response_msg is None:
        return JSONResponse({"error": "No response received"}, status_code=500)

    root = response_msg.message.root
    if hasattr(root, "result"):
        aliases = {alias: real for alias, real in target.engine.alias_cache.items()}
        return JSONResponse({"result": root.result, "aliases": aliases})
    if hasattr(root, "error"):
        err = root.error
        msg = err.message if hasattr(err, "message") else str(err)
        return JSONResponse({"error": msg}, status_code=400)
    return JSONResponse({"error": "Unexpected response"}, status_code=500)
