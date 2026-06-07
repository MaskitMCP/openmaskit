"""Custom target CRUD API routes."""

from __future__ import annotations

import logging
import re

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse

from openmaskit.container import (
    extract_container_name,
    is_container_run_command,
    validate_user_container_name,
)
from openmaskit.web.routes._http_config import clean_http_headers

logger = logging.getLogger(__name__)

_DELETE_DISCONNECT_TIMEOUT = 15


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:64]


# Re-exported for tests that imported the private name.
_clean_http_headers = clean_http_headers


def _build_config(body: dict) -> tuple[dict | None, str | None]:
    """Build a config dict from request body. Returns (config, error)."""
    transport = body.get("transport", "stdio")

    if transport == "stdio":
        command = body.get("command", "").strip()
        if not command:
            return None, "command is required for stdio transport"
        args = body.get("args", []) or []

        # If the user supplied --name on a container `run` command, validate
        # it now so the failure surfaces at submission rather than activation.
        if is_container_run_command(command, args):
            user_name = extract_container_name(args)
            if user_name is not None:
                err = validate_user_container_name(user_name)
                if err is not None:
                    return None, err

        config = {
            "transport": "stdio",
            "command": command,
            "args": args,
            "env": body.get("env", {}),
        }
    elif transport == "http":
        url = body.get("url", "").strip()
        if not url:
            return None, "url is required for http transport"
        config: dict = {"transport": "http", "url": url}
        oauth = body.get("oauth")
        oauth_mode = body.get("oauth_mode", "manual")

        if oauth and isinstance(oauth, dict) and any(oauth.values()):
            # Preserve all OAuth fields (DCR or manual)
            config["oauth"] = {
                k: v for k, v in oauth.items() if v
            }

        headers, header_err = clean_http_headers(body.get("headers"))
        if header_err:
            return None, header_err
        if headers:
            # Reject Authorization when OAuth is configured: the OAuth flow
            # sets that header itself and a stale value would silently win or
            # collide. The model validator also enforces this, but checking
            # here gives a friendlier 400 from the API.
            if "oauth" in config:
                for name in headers:
                    if name.lower() == "authorization":
                        return (
                            None,
                            "headers must not include 'Authorization' when "
                            "oauth is configured",
                        )
            config["headers"] = headers
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


async def custom_target_activate(request: Request):
    """
    Activate a previously deactivated custom server.

    POST /api/custom-targets/{target_id}/activate
    """
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    target_id = request.path_params["target_id"]

    # Validate server exists
    existing = await store.get_server(target_id)
    if not existing:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    # Check if already active
    if target_id in state.targets:
        return JSONResponse({"error": "Target is already active"}, status_code=409)

    # Load config from database
    config = existing["config"]

    # Attempt connection
    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(target_id, config)
            connected = True
            await store.activate_server(target_id)  # Update DB only if connection succeeds
        except Exception as exc:
            # anyio wraps task-group failures in an ExceptionGroup whose
            # str() is "unhandled errors in a TaskGroup (N sub-exception)" —
            # useless on its own. Unwrap to the real cause and log a full
            # traceback so misconfigured upstreams (dead OAuth tokens, bad
            # URL, etc.) are diagnosable from the terminal.
            if hasattr(exc, "exceptions") and exc.exceptions:
                error_msg = str(exc.exceptions[0])
            else:
                error_msg = str(exc)
            logger.exception(
                "Failed to activate custom target %s: %s", target_id, error_msg
            )

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result)


async def custom_target_deactivate(request: Request):
    """
    Deactivate a custom server (disconnect but keep config).

    POST /api/custom-targets/{target_id}/deactivate
    """
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    target_id = request.path_params["target_id"]

    # Validate server exists
    existing = await store.get_server(target_id)
    if not existing:
        return JSONResponse({"error": "Target not found"}, status_code=404)

    # Disconnect if currently connected
    if manager and target_id in state.targets:
        try:
            await manager.remove_target(target_id)
        except Exception as exc:
            logger.warning("Error disconnecting %s for deactivation: %s", target_id, exc)

    # Mark as inactive in database
    await store.deactivate_server(target_id)
    return JSONResponse({"ok": True})
