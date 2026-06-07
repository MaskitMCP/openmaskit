"""OAuth callback handler.

Receives the redirect from the authorization server after the user approves
the install (or reauthorize). Three modes share this one endpoint:

- ``broker``: hosted broker swaps the code via ``auth.maskitmcp.com``.
- ``byo`` / ``dcr``: OpenMaskit posts to the AS's ``token_endpoint`` directly
  with the PKCE verifier stashed at install-prep time.

State validation (existence, expiry, handle match) is identical across modes;
only the code-exchange step branches.
"""

from __future__ import annotations

import anyio
import json
import logging
import time
from pathlib import Path

from starlette.requests import Request
from starlette.responses import RedirectResponse

from openmaskit.oauth.code_exchange import exchange_code
from openmaskit.security import validate_server_id, write_token_file

logger = logging.getLogger(__name__)

# OAuth state expiry (15 minutes)
OAUTH_STATE_TTL = 900


async def cleanup_expired_oauth_states(oauth_states: dict, interval: int = 300):
    """Remove expired OAuth state entries every `interval` seconds."""
    while True:
        await anyio.sleep(interval)
        now = time.time()
        expired = [
            state_id for state_id, data in oauth_states.items()
            if now - data.get("timestamp", 0) > OAUTH_STATE_TTL
        ]
        for state_id in expired:
            oauth_states.pop(state_id, None)
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired OAuth state(s)")


def _oauth_token_path(manager, handle: str) -> Path:
    if manager:
        return Path(manager._store_path).expanduser().parent / "oauth" / f"{handle}.json"
    return Path("~/.openmaskit/oauth").expanduser() / f"{handle}.json"


def _normalize_expires_in(expires_in):
    if expires_in and expires_in > 31536000:  # > 1 year in seconds → likely ms
        return expires_in // 1000
    return expires_in


async def oauth_callback(request: Request):
    """Handle OAuth callback after user authorization."""
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = request.app.state.backend_client
    oauth_states = request.app.state.oauth_states

    handle = request.path_params["handle"]

    try:
        handle = validate_server_id(handle)
    except ValueError as e:
        logger.error(f"Invalid handle in OAuth callback: {e}")
        return RedirectResponse(
            "/marketplace?error=invalid_handle&message=Invalid server identifier",
            status_code=302,
        )

    code = request.query_params.get("code")
    csrf_state = request.query_params.get("state")
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")

    if error:
        logger.warning(f"OAuth error for {handle}: {error} - {error_description}")
        return RedirectResponse(
            f"/marketplace?error={error}&message={error_description or 'OAuth failed'}",
            status_code=302,
        )

    if not csrf_state or csrf_state not in oauth_states:
        logger.error(f"Invalid or expired OAuth state for {handle}")
        return RedirectResponse(
            "/marketplace?error=invalid_state&message=Invalid or expired OAuth session",
            status_code=302,
        )

    state_data = oauth_states.get(csrf_state)
    expected_handle = state_data["handle"]

    if time.time() - state_data["timestamp"] > OAUTH_STATE_TTL:
        logger.error(f"Expired OAuth state for {handle}")
        oauth_states.pop(csrf_state, None)
        return RedirectResponse(
            "/marketplace?error=expired_state&message=OAuth session expired",
            status_code=302,
        )

    if handle != expected_handle:
        logger.error(f"Handle mismatch: expected {expected_handle}, got {handle}")
        return RedirectResponse(
            "/marketplace?error=invalid_handle&message=Server handle mismatch",
            status_code=302,
        )

    oauth_states.pop(csrf_state, None)

    mode = state_data.get("mode", "broker")
    if mode == "broker":
        return await _finish_broker_install(
            handle=handle,
            state_data=state_data,
            code=code,
            backend_client=backend_client,
            manager=manager,
            store=store,
        )
    if mode in ("byo", "dcr"):
        return await _finish_local_install(
            handle=handle,
            state_data=state_data,
            code=code,
            manager=manager,
            store=store,
            proxy_state=state,
        )

    logger.error(f"Unknown OAuth mode {mode!r} for {handle}")
    return RedirectResponse(
        f"/marketplace?error=invalid_mode&message=Unknown OAuth mode {mode}",
        status_code=302,
    )


async def _finish_broker_install(
    *, handle, state_data, code, backend_client, manager, store
):
    server_uuid = state_data["server_id"]
    try:
        token_data = await backend_client.exchange_code(
            server_id=server_uuid, code=code
        )
        logger.info(f"Successfully exchanged code for token: {handle}")
    except Exception as e:
        logger.error(f"Token exchange failed for {handle}: {e}")
        return RedirectResponse(
            f"/marketplace?error=token_exchange&message={str(e)}", status_code=302
        )

    token_path = _oauth_token_path(manager, handle)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    token_file_data = {
        "tokens": {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
            "scope": token_data.get("scope"),
            "expires_in": _normalize_expires_in(token_data.get("expires_in")),
            "refresh_token": token_data.get("refresh_token"),
            "created_at": time.time(),
        },
        # No client_info — backend manages OAuth client credentials.
    }
    write_token_file(token_path, token_file_data)
    logger.info(f"Encrypted token stored at {token_path}")

    try:
        server_info = await backend_client.get_server_info(server_uuid)
        if not server_info:
            logger.error(f"Server info not found for UUID {server_uuid}")
            return RedirectResponse(
                "/marketplace?error=not_found&message=Server not found in backend",
                status_code=302,
            )
        if not server_info.get("mcp_host"):
            logger.error(f"No mcp_host returned for {handle}")
            return RedirectResponse(
                "/marketplace?error=no_mcp_host&message=Server configuration incomplete",
                status_code=302,
            )
    except Exception as e:
        logger.error(f"Failed to fetch server info for {handle}: {e}")
        return RedirectResponse(
            f"/marketplace?error=backend_error&message={str(e)}",
            status_code=302,
        )

    from openmaskit.web.routes.marketplace import _build_config_from_server_info

    try:
        config = _build_config_from_server_info(server_info)
        icon_url = server_info.get("icon_url")
        await store.install_server(handle, server_info["name"], config, icon_url)
        await manager.add_target(handle, config)
        logger.info(f"Successfully installed and connected: {handle}")
        return RedirectResponse(
            f"/marketplace?success=true&installed={handle}", status_code=302
        )
    except Exception as e:
        logger.exception(f"Failed to connect {handle}")
        if hasattr(e, "exceptions") and e.exceptions:
            error_msg = str(e.exceptions[0])
        else:
            error_msg = str(e)
        return RedirectResponse(
            f"/marketplace?error=connection_failed&message={error_msg}", status_code=302
        )


async def _finish_local_install(
    *, handle, state_data, code, manager, store, proxy_state
):
    """Finish a BYO or DCR install/reauthorize.

    Exchanges the code against the AS's ``token_endpoint`` using the PKCE
    verifier we stashed at install-prep time, persists tokens at the same
    path the runtime SDK reads from, and either installs+connects (fresh
    install) or remove+add+activates (reauthorize).
    """
    if not code:
        return RedirectResponse(
            "/marketplace?error=missing_code&message=Authorization server did not return a code",
            status_code=302,
        )

    try:
        token_data = await exchange_code(
            state_data["token_endpoint"],
            code=code,
            redirect_uri=state_data["redirect_uri"],
            client_id=state_data["client_id"],
            code_verifier=state_data["code_verifier"],
            client_secret=state_data.get("client_secret"),
            auth_method=state_data.get("auth_method", "client_secret_post"),
            resource=state_data.get("resource"),
        )
    except RuntimeError as e:
        logger.error(f"Token exchange failed for {handle}: {e}")
        return RedirectResponse(
            f"/marketplace?error=token_exchange&message={str(e)}", status_code=302
        )

    token_path = _oauth_token_path(manager, handle)
    token_path.parent.mkdir(parents=True, exist_ok=True)

    token_file_data = {
        "tokens": {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
            "scope": token_data.get("scope") or state_data.get("scope"),
            "expires_in": _normalize_expires_in(token_data.get("expires_in")),
            "refresh_token": token_data.get("refresh_token"),
            "created_at": time.time(),
        },
        # client_info was already persisted by install_flow.prepare_oauth_install.
    }
    write_token_file(token_path, token_file_data)
    logger.info(f"Encrypted token stored at {token_path}")

    config = state_data["config"]
    reauthorize = state_data.get("reauthorize", False)

    try:
        if reauthorize:
            if handle in proxy_state.targets:
                await manager.remove_target(handle)
            await manager.add_target(handle, config)
            await store.activate_server(handle)
            logger.info(f"Reauthorized and reconnected {handle}")
        else:
            server_info = state_data.get("server_info") or {}
            name = server_info.get("name") or handle
            icon_url = state_data.get("icon_url")
            await store.install_server(handle, name, config, icon_url)
            await manager.add_target(handle, config)
            logger.info(f"Installed and connected {handle}")
        return RedirectResponse(
            f"/marketplace?success=true&installed={handle}", status_code=302
        )
    except Exception as e:
        logger.exception(f"Failed to connect {handle} after OAuth")
        if hasattr(e, "exceptions") and e.exceptions:
            error_msg = str(e.exceptions[0])
        else:
            error_msg = str(e)
        return RedirectResponse(
            f"/marketplace?error=connection_failed&message={error_msg}", status_code=302
        )
