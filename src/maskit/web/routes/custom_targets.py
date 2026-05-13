"""Custom target CRUD API routes."""

from __future__ import annotations

import logging
import re

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

_DELETE_DISCONNECT_TIMEOUT = 15


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:64]


def _build_config(body: dict) -> tuple[dict | None, str | None]:
    """Build a config dict from request body. Returns (config, error)."""
    transport = body.get("transport", "stdio")

    if transport == "stdio":
        command = body.get("command", "").strip()
        if not command:
            return None, "command is required for stdio transport"
        config = {
            "transport": "stdio",
            "command": command,
            "args": body.get("args", []),
            "env": body.get("env", {}),
        }
    elif transport == "http":
        url = body.get("url", "").strip()
        if not url:
            return None, "url is required for http transport"
        config: dict = {"transport": "http", "url": url}
        oauth = body.get("oauth")
        if oauth and isinstance(oauth, dict) and any(oauth.values()):
            config["oauth"] = {
                k: v for k, v in oauth.items() if v
            }
    else:
        return None, "transport must be 'stdio' or 'http'"

    return config, None


async def custom_target_create(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    body = await request.json()
    name = body.get("name", "").strip()

    if not name:
        return JSONResponse({"error": "name is required"}, status_code=400)

    server_id = _slugify(name)
    if not server_id:
        return JSONResponse({"error": "name produces invalid ID"}, status_code=400)

    if server_id in state.config_target_ids:
        return JSONResponse({"error": "ID conflicts with a config-file target"}, status_code=409)

    existing = await store.get_server(server_id)
    if existing:
        return JSONResponse({"error": "A target with this ID already exists"}, status_code=409)

    config, error = _build_config(body)
    if error:
        return JSONResponse({"error": error}, status_code=400)

    await store.install_server(server_id, name, config)

    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(server_id, config)
            connected = True
        except Exception as exc:
            logger.warning("Failed to connect custom target %s: %s", server_id, exc)
            error_msg = str(exc)
            await store.deactivate_server(server_id)

    result = {"ok": True, "server_id": server_id, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result, status_code=201)


async def custom_target_get(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    target_id = request.path_params["target_id"]

    if target_id in state.config_target_ids:
        return JSONResponse({"error": "Cannot view config for config-file targets"}, status_code=403)

    record = await store.get_server(target_id)
    if not record:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    return JSONResponse({
        "id": record["id"],
        "name": record["name"],
        "config": record["config"],
        "active": record["active"],
    })


async def custom_target_update(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    target_id = request.path_params["target_id"]

    if target_id in state.config_target_ids:
        return JSONResponse({"error": "Cannot edit config-file targets"}, status_code=403)

    existing = await store.get_server(target_id)
    if not existing:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    body = await request.json()
    name = body.get("name", existing["name"]).strip()

    config, error = _build_config(body)
    if error:
        return JSONResponse({"error": error}, status_code=400)

    if manager and target_id in state.targets:
        try:
            await manager.remove_target(target_id)
        except Exception as exc:
            logger.warning("Error disconnecting %s for update: %s", target_id, exc)

    await store.update_server(target_id, name, config)

    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(target_id, config)
            connected = True
        except Exception as exc:
            logger.warning("Failed to reconnect %s after update: %s", target_id, exc)
            error_msg = str(exc)
            await store.deactivate_server(target_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result)


async def custom_target_delete(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    target_id = request.path_params["target_id"]

    if target_id in state.config_target_ids:
        return JSONResponse({"error": "Cannot delete config-file targets"}, status_code=403)

    existing = await store.get_server(target_id)
    if not existing:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    if manager and target_id in state.targets:
        try:
            with anyio.fail_after(_DELETE_DISCONNECT_TIMEOUT):
                await manager.remove_target(target_id)
        except TimeoutError:
            logger.warning("Timed out disconnecting %s, forcing removal", target_id)
            state.targets.pop(target_id, None)
        except Exception as exc:
            logger.warning("Error disconnecting %s for delete: %s", target_id, exc)
            state.targets.pop(target_id, None)

    await store.uninstall_server(target_id)
    return JSONResponse({"ok": True})
