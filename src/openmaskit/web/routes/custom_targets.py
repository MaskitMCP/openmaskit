"""Custom target CRUD API routes.

These routes live at ``/api/targets/custom/{target_id}/*`` and are restricted
to rows where ``source == 'custom'``. Marketplace-source rows are 403'd here
even when the FE accidentally targets the wrong endpoint — same applies to
config-file targets. The gate runs synchronously before any DB write or
connection attempt so a wrong-route request can't corrupt state or stall on
a reconnect timeout.
"""

from __future__ import annotations

import logging
import re

import anyio
from starlette.requests import Request
from starlette.responses import JSONResponse

from openmaskit.config_serde import load_display_config, load_runtime_config
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


async def _resolve_custom_target(state, store, target_id: str):
    """Validate that ``target_id`` is editable through the custom-target API.

    Returns either ``(record, None)`` on success or ``(None, JSONResponse)``
    with the appropriate error. Config-file targets and marketplace-source
    rows are rejected with 403 — marketplace servers must be managed through
    ``/api/marketplace/*`` instead.
    """
    if target_id in state.config_target_ids:
        return None, JSONResponse(
            {"error": "Config-file targets are not editable via the dashboard"},
            status_code=403,
        )
    record = await store.get_server(target_id)
    if not record:
        return None, JSONResponse({"error": "Target not found"}, status_code=404)
    if record["source"] != "custom":
        return None, JSONResponse(
            {
                "error": "This server was installed from the marketplace; "
                "manage it from the Marketplace page.",
            },
            status_code=403,
        )
    return record, None


def _split_typed_entries(raw: dict | None) -> tuple[dict[str, str], dict[str, str]]:
    """Split a ``{KEY: {value, type}}`` (or bare-string) map into a flat
    ``{KEY: value_str}`` map for validation plus a sibling ``{KEY: type}`` map.

    Tolerates the legacy bare-string shape (``{KEY: "value"}``) by defaulting
    each entry's type to ``secret`` — the conservative choice for the redactor.
    """
    raw = raw or {}
    flat: dict[str, str] = {}
    types: dict[str, str] = {}
    for k, v in raw.items():
        if isinstance(v, dict) and "value" in v and "type" in v:
            flat[k] = v["value"] if v["value"] is not None else ""
            types[k] = v["type"]
        else:
            flat[k] = v if isinstance(v, str) else ""
            types[k] = "secret"
    return flat, types


def _build_config(body: dict) -> tuple[dict | None, str | None]:
    """Build a config dict from request body. Returns (config, error).

    env and headers are emitted as the typed ``{KEY: {value, type}}`` shape
    the storage layer expects. Header values still pass through
    ``clean_http_headers`` for whitespace/CR-LF/reserved-name validation; the
    type tags are reattached after cleaning.
    """
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

        env_values, env_types = _split_typed_entries(body.get("env"))
        env_typed = {
            k: {"value": env_values[k], "type": env_types[k]}
            for k in env_values
        }

        config = {
            "transport": "stdio",
            "command": command,
            "args": args,
            "env": env_typed,
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

        header_values, header_types = _split_typed_entries(body.get("headers"))
        cleaned, header_err = clean_http_headers(header_values)
        if header_err:
            return None, header_err
        if cleaned:
            # Reject Authorization when OAuth is configured: the OAuth flow
            # sets that header itself and a stale value would silently win or
            # collide. The model validator also enforces this, but checking
            # here gives a friendlier 400 from the API.
            if "oauth" in config:
                for name in cleaned:
                    if name.lower() == "authorization":
                        return (
                            None,
                            "headers must not include 'Authorization' when "
                            "oauth is configured",
                        )
            config["headers"] = {
                k: {"value": v, "type": header_types.get(k, "secret")}
                for k, v in cleaned.items()
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

    await store.install_server(
        server_id,
        name,
        source="custom",
        backend_id=None,
        config=config,
    )

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
    """Read a custom target for the Edit modal pre-fill.

    Returns the on-disk shape (typed env/headers) with secret values replaced
    by ``"••••••••"`` — no plaintext secret ever crosses the API boundary.
    The FE renders password inputs empty and the matching ``custom_target_update``
    preserves the stored secret when the user leaves them blank.
    """
    state = request.app.state.proxy_state
    store = state.store
    target_id = request.path_params["target_id"]

    record, err = await _resolve_custom_target(state, store, target_id)
    if err:
        return err

    try:
        config = load_display_config(record["config_json"])
    except Exception as exc:
        logger.exception("Failed to parse config_json for %s", target_id)
        return JSONResponse({"error": f"Config not parseable: {exc}"}, status_code=500)

    return JSONResponse({
        "id": record["id"],
        "name": record["name"],
        "config": config,
        "active": record["active"],
    })


async def custom_target_update(request: Request):
    """Update a custom target.

    The store merges the incoming config into the stored one: secret fields
    the user left blank in the Edit modal (e.g. ``client_secret``, env values
    typed ``secret``) keep their stored encrypted value. Non-secret fields
    are replaced verbatim.

    The reconnect runs against the merged, decrypted runtime view so the
    connection sees real secrets even if the user didn't retype them.
    """
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager

    target_id = request.path_params["target_id"]

    existing, err = await _resolve_custom_target(state, store, target_id)
    if err:
        return err

    body = await request.json()
    name = body.get("name", existing["name"]).strip()

    incoming_config, error = _build_config(body)
    if error:
        return JSONResponse({"error": error}, status_code=400)

    if manager and target_id in state.targets:
        try:
            await manager.remove_target(target_id)
        except Exception as exc:
            logger.warning("Error disconnecting %s for update: %s", target_id, exc)

    await store.update_server(target_id, name, incoming_config)

    # Re-read so we get the merged config (with stored secrets restored where
    # the user left fields blank) and reconnect against the runtime view.
    refreshed = await store.get_server(target_id)
    runtime_config = load_runtime_config(refreshed["config_json"])

    connected = False
    error_msg = None
    if manager:
        try:
            await manager.add_target(target_id, runtime_config)
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

    _, err = await _resolve_custom_target(state, store, target_id)
    if err:
        return err

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

    existing, err = await _resolve_custom_target(state, store, target_id)
    if err:
        return err

    # Check if already active
    if target_id in state.targets:
        return JSONResponse({"error": "Target is already active"}, status_code=409)

    # Load config from database (runtime view: decrypted, flattened).
    try:
        config = load_runtime_config(existing["config_json"])
    except Exception as exc:
        logger.exception(
            "Cannot activate %s: config not loadable", target_id
        )
        return JSONResponse(
            {"error": f"Server config not loadable: {exc}"}, status_code=500
        )

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

    _, err = await _resolve_custom_target(state, store, target_id)
    if err:
        return err

    # Disconnect if currently connected
    if manager and target_id in state.targets:
        try:
            await manager.remove_target(target_id)
        except Exception as exc:
            logger.warning("Error disconnecting %s for deactivation: %s", target_id, exc)

    # Mark as inactive in database
    await store.deactivate_server(target_id)
    return JSONResponse({"ok": True})
