"""Marketplace API routes."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

logger = logging.getLogger(__name__)

CATALOG_PATH = Path(__file__).parent.parent.parent.parent.parent / "marketplace.json"
STATIC_DIR = Path(__file__).parent.parent / "static"


def _load_catalog() -> list[dict]:
    if not CATALOG_PATH.exists():
        return []
    with open(CATALOG_PATH) as f:
        return json.load(f)


def _find_catalog_entry(server_id: str) -> dict | None:
    for entry in _load_catalog():
        if entry["id"] == server_id:
            return entry
    return None


def _build_config_from_catalog(entry: dict, env_vars: dict[str, str] | None = None,
                               oauth_vars: dict[str, str] | None = None) -> dict:
    """Build an upstream config dict from a catalog entry + user-provided env/oauth vars."""
    config: dict = {"transport": entry["transport"]}
    if entry["transport"] == "http":
        config["url"] = entry["url"]
        if entry.get("oauth") is not None:
            oauth_config = dict(entry["oauth"])
            if oauth_vars:
                oauth_config.update(oauth_vars)
            config["oauth"] = oauth_config
    else:
        config["command"] = entry["command"]
        config["args"] = entry.get("args", [])
        if env_vars:
            config["env"] = env_vars
    return config


async def marketplace_page(request: Request):
    return FileResponse(STATIC_DIR / "marketplace.html")


async def marketplace_list(request: Request):
    state = request.app.state.proxy_state
    store = state.store

    catalog = _load_catalog()
    installed = await store.get_installed_servers()
    installed_map = {s["id"]: s for s in installed}

    servers = []
    for entry in catalog:
        server_id = entry["id"]
        record = installed_map.get(server_id)
        target = state.get_target(server_id)

        servers.append({
            "id": server_id,
            "name": entry["name"],
            "description": entry["description"],
            "icon": entry.get("icon", ""),
            "official": entry.get("official", False),
            "tags": entry.get("tags", []),
            "env_vars": entry.get("env_vars", []),
            "oauth_vars": entry.get("oauth_vars", []),
            "installed": record is not None,
            "active": record["active"] if record else False,
            "connected": target is not None and target.initialized if record and record["active"] else False,
        })

    return JSONResponse({"servers": servers})


async def marketplace_install(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    body = await request.json()
    server_id = body.get("server_id", "").strip()
    env_vars = body.get("env_vars", {})
    oauth_vars = body.get("oauth_vars", {})

    if not server_id:
        return JSONResponse({"error": "server_id is required"}, status_code=400)

    entry = _find_catalog_entry(server_id)
    if not entry:
        return JSONResponse({"error": "Server not found in catalog"}, status_code=404)

    existing = await store.get_server(server_id)
    if existing:
        return JSONResponse({"error": "Server already installed"}, status_code=409)

    if server_id in state.targets:
        return JSONResponse({"error": "Server ID conflicts with existing config target"}, status_code=409)

    required_vars = entry.get("env_vars", [])
    missing = [v for v in required_vars if v not in env_vars or not env_vars[v]]
    if missing:
        return JSONResponse(
            {"error": f"Missing required environment variables: {', '.join(missing)}"},
            status_code=400,
        )

    required_oauth = entry.get("oauth_vars", [])
    missing_oauth = [v for v in required_oauth if v not in oauth_vars or not oauth_vars[v]]
    if missing_oauth:
        return JSONResponse(
            {"error": f"Missing required OAuth credentials: {', '.join(missing_oauth)}"},
            status_code=400,
        )

    config = _build_config_from_catalog(entry, env_vars or None, oauth_vars or None)

    # Clear stale OAuth tokens so a fresh auth flow triggers
    if manager:
        oauth_path = Path(manager._store_path).expanduser().parent / "oauth" / f"{server_id}.json"
        if oauth_path.exists():
            oauth_path.unlink()

    await store.install_server(server_id, entry["name"], config)

    connected = False
    error_msg = None
    if manager:
        try:
            target = await manager.add_target(server_id, config)
            connected = True
        except Exception as exc:
            logger.warning("Failed to connect marketplace server %s: %s", server_id, exc)
            error_msg = str(exc)
            await store.deactivate_server(server_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result, status_code=201)


async def marketplace_deactivate(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    body = await request.json()
    server_id = body.get("server_id", "").strip()

    if not server_id:
        return JSONResponse({"error": "server_id is required"}, status_code=400)

    existing = await store.get_server(server_id)
    if not existing:
        return JSONResponse({"error": "Server not installed"}, status_code=404)

    if manager:
        try:
            await manager.remove_target(server_id)
        except Exception as exc:
            logger.warning("Error removing target %s: %s", server_id, exc)

    await store.deactivate_server(server_id)
    return JSONResponse({"ok": True})


async def marketplace_activate(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    body = await request.json()
    server_id = body.get("server_id", "").strip()

    if not server_id:
        return JSONResponse({"error": "server_id is required"}, status_code=400)

    existing = await store.get_server(server_id)
    if not existing:
        return JSONResponse({"error": "Server not installed"}, status_code=404)

    if server_id in state.targets:
        return JSONResponse({"error": "Server is already active"}, status_code=409)

    config = existing["config"]
    connected = False
    error_msg = None

    if manager:
        try:
            await manager.add_target(server_id, config)
            connected = True
        except Exception as exc:
            logger.warning("Failed to reconnect marketplace server %s: %s", server_id, exc)
            error_msg = str(exc)

    if connected:
        await store.activate_server(server_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result)
