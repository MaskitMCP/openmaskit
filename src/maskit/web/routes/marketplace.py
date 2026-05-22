"""Marketplace API routes."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from uuid import uuid4

from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse

from maskit.security import validate_server_id

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent.parent / "static"


def _build_config_from_server_info(server_info: dict, user_env_vars: dict | None = None) -> dict:
    """Build upstream config from backend server info.

    Args:
        server_info: Server configuration from backend
        user_env_vars: User-provided environment variable values (for stdio servers)
    """
    transport = server_info.get("transport_type", "http")

    if transport == "http":
        config = {
            "transport": "http",
            "url": server_info["mcp_host"],
        }
        # Add OAuth config if the server requires OAuth
        # Token is already stored by oauth_callback, upstream will load it from file
        if server_info.get("requires_oauth"):
            config["oauth"] = {
                "type": "oauth2.1",
                "client_id": "managed-by-backend",  # Placeholder - backend manages this
                "scope": "default",  # Placeholder - backend manages this
            }
        return config
    else:  # stdio (local/docker)
        meta = server_info.get("meta", {})
        # Use user-provided env vars if available, otherwise use backend placeholders
        env = user_env_vars if user_env_vars else meta.get("env", {})
        return {
            "transport": "stdio",
            "command": meta.get("command", ""),
            "args": meta.get("args", []),
            "env": env,
        }


async def marketplace_page(request: Request):
    return FileResponse(STATIC_DIR / "marketplace.html")


async def marketplace_list(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    backend_client = getattr(request.app.state, "backend_client", None)

    if not backend_client:
        return JSONResponse({
            "servers": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0}
        })

    # Extract pagination and search params
    page = int(request.query_params.get("page", 1))
    size = int(request.query_params.get("size", 12))
    query = request.query_params.get("q", "").strip() or None

    # Fetch from backend with pagination and search
    catalog_response = await backend_client.get_catalog(page=page, size=size, query=query)
    backend_catalog = catalog_response["data"]
    meta = catalog_response["meta"]

    installed = await store.get_installed_servers()
    installed_map = {s["id"]: s for s in installed}

    servers = []
    for entry in backend_catalog:
        handle = entry.get("handle")
        if not handle:
            continue

        server_id = handle  # Use handle as local ID
        record = installed_map.get(server_id)
        target = state.get_target(server_id)

        # Extract env var names from meta.env (keys are var names, values are placeholders)
        meta_env = entry.get("meta", {})
        env_vars = list(meta_env.get("env", {}).keys()) if meta_env else []

        servers.append({
            "id": server_id,
            "backend_id": entry["id"],  # UUID for backend API
            "handle": handle,
            "name": entry["name"],
            "description": entry.get("description", ""),
            "icon_url": entry.get("icon_url"),
            "category": entry.get("category"),
            "requires_oauth": entry.get("requires_oauth", False),
            "env_vars": env_vars,  # Array of env var names to prompt for
            "installed": record is not None,
            "active": record["active"] if record else False,
            "connected": target is not None and target.initialized if record and record["active"] else False,
        })

    return JSONResponse({"servers": servers, "meta": meta})


async def marketplace_install(request: Request):
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = getattr(request.app.state, "backend_client", None)
    oauth_states = getattr(request.app.state, "oauth_states", {})

    if not backend_client:
        return JSONResponse({"error": "Backend not available"}, status_code=503)

    body = await request.json()
    server_id = body.get("server_id", "").strip()  # handle
    backend_id = body.get("backend_id", "").strip()  # UUID

    if not server_id or not backend_id:
        return JSONResponse({"error": "server_id and backend_id required"}, status_code=400)

    try:
        server_id = validate_server_id(server_id)
    except ValueError:
        return JSONResponse(
            {"error": "Invalid server_id format"},
            status_code=400
        )

    # Check if server already installed in DB
    existing = await store.get_server(server_id)
    if existing:
        return JSONResponse({"error": "Server already installed"}, status_code=409)

    # Check if there's a config-file target with this name
    if server_id in state.config_target_ids:
        return JSONResponse(
            {"error": f"Server '{server_id}' conflicts with a config-file target"},
            status_code=409,
        )

    # Fetch server details from backend
    server_info = await backend_client.get_server_info(backend_id)
    if not server_info:
        return JSONResponse({"error": "Server not found"}, status_code=404)

    # If OAuth required, initiate OAuth flow
    if server_info.get("requires_oauth"):
        csrf_state = str(uuid4())
        oauth_states[csrf_state] = {
            "server_id": backend_id,
            "handle": server_id,
            "timestamp": time.time(),
        }

        base_url = f"{request.url.scheme}://{request.url.netloc}"
        redirect_uri = f"{base_url}/oauth/callback/{server_id}"
        oauth_url = backend_client.get_oauth_authorize_url(
            server_id=backend_id, state=csrf_state, redirect_uri=redirect_uri
        )

        logger.info(f"Initiating OAuth flow for {server_id}: {oauth_url}")
        return JSONResponse({"ok": True, "requires_oauth": True, "oauth_url": oauth_url})

    # Non-OAuth server: connect immediately
    # Get user-provided env vars from request
    user_env_vars = body.get("env_vars", {})
    config = _build_config_from_server_info(server_info, user_env_vars)
    icon_url = server_info.get("icon_url")
    await store.install_server(server_id, server_info["name"], config, icon_url)

    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(server_id, config)
            connected = True
            logger.info(f"Successfully connected non-OAuth server: {server_id}")
        except Exception as exc:
            logger.exception(f"Failed to connect {server_id}")
            # Unwrap ExceptionGroup to get the real error
            if hasattr(exc, 'exceptions') and exc.exceptions:
                error_msg = str(exc.exceptions[0])
            else:
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
            logger.exception("Failed to reconnect marketplace server %s", server_id)
            # Unwrap ExceptionGroup to get the real error
            if hasattr(exc, 'exceptions') and exc.exceptions:
                error_msg = str(exc.exceptions[0])
            else:
                error_msg = str(exc)

    if connected:
        await store.activate_server(server_id)

    result = {"ok": True, "connected": connected}
    if error_msg:
        result["error"] = error_msg
    return JSONResponse(result)
