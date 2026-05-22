"""OAuth callback handler for backend-initiated OAuth flows."""

from __future__ import annotations

import anyio
import json
import logging
import time
from pathlib import Path

from starlette.requests import Request
from starlette.responses import RedirectResponse

from maskit.security import validate_server_id, write_token_file

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


async def oauth_callback(request: Request):
    """Handle OAuth callback from backend after user authorization."""
    state = request.app.state.proxy_state
    store = state.store
    manager = state.target_manager
    backend_client = request.app.state.backend_client
    oauth_states = request.app.state.oauth_states

    handle = request.path_params["handle"]

    # Validate handle before using in file paths
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

    # Handle OAuth errors
    if error:
        logger.warning(f"OAuth error for {handle}: {error} - {error_description}")
        return RedirectResponse(
            f"/marketplace?error={error}&message={error_description or 'OAuth failed'}",
            status_code=302,
        )

    # Validate CSRF state
    if not csrf_state or csrf_state not in oauth_states:
        logger.error(f"Invalid or expired OAuth state for {handle}")
        return RedirectResponse(
            "/marketplace?error=invalid_state&message=Invalid or expired OAuth session",
            status_code=302,
        )

    # Get state data but don't pop yet (avoid race condition)
    state_data = oauth_states.get(csrf_state)
    server_uuid = state_data["server_id"]
    expected_handle = state_data["handle"]

    # Check state not expired (15 min)
    if time.time() - state_data["timestamp"] > 900:
        logger.error(f"Expired OAuth state for {handle}")
        # Clean up expired state
        oauth_states.pop(csrf_state, None)
        return RedirectResponse(
            "/marketplace?error=expired_state&message=OAuth session expired",
            status_code=302,
        )

    # Validate handle matches
    if handle != expected_handle:
        logger.error(f"Handle mismatch: expected {expected_handle}, got {handle}")
        # Don't pop state - might be user error, allow retry
        return RedirectResponse(
            "/marketplace?error=invalid_handle&message=Server handle mismatch",
            status_code=302,
        )

    # All validations passed - now pop the state (consume it)
    oauth_states.pop(csrf_state, None)

    # Exchange code for token
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

    # Store token locally (use handle, not UUID, to match connect_upstream lookup)
    if manager:
        oauth_dir = Path(manager._store_path).expanduser().parent / "oauth"
    else:
        # Fallback if no manager
        oauth_dir = Path("~/.maskit/oauth").expanduser()
    oauth_dir.mkdir(parents=True, exist_ok=True)
    token_path = oauth_dir / f"{handle}.json"

    # Convert expires_in from milliseconds to seconds if needed
    expires_in = token_data.get("expires_in")
    if expires_in and expires_in > 31536000:  # > 1 year in seconds, likely milliseconds
        expires_in = expires_in // 1000

    token_file_data = {
        "tokens": {
            "access_token": token_data["access_token"],
            "token_type": token_data.get("token_type", "Bearer"),
            "scope": token_data.get("scope"),
            "expires_in": expires_in,
            "refresh_token": token_data.get("refresh_token"),
        },
        # No client_info - backend manages OAuth client credentials
    }

    write_token_file(token_path, token_file_data)
    logger.info(f"Encrypted token stored at {token_path}")

    # Fetch server details from backend (includes mcp_host)
    try:
        server_info = await backend_client.get_server_info(server_uuid)
        if not server_info:
            logger.error(f"Server info not found for UUID {server_uuid}")
            return RedirectResponse(
                "/marketplace?error=not_found&message=Server not found in backend",
                status_code=302,
            )

        mcp_host = server_info.get("mcp_host")
        if not mcp_host:
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

    # Build config from backend response
    from maskit.web.routes.marketplace import _build_config_from_server_info

    try:
        config = _build_config_from_server_info(server_info)
        icon_url = server_info.get("icon_url")
        await store.install_server(handle, server_info["name"], config, icon_url)
        await manager.add_target(handle, config)
        logger.info(f"Successfully installed and connected: {handle} to {mcp_host}")
        return RedirectResponse(
            f"/marketplace?success=true&installed={handle}", status_code=302
        )
    except Exception as e:
        logger.exception(f"Failed to connect {handle}")
        # Unwrap ExceptionGroup to get the real error
        if hasattr(e, 'exceptions') and e.exceptions:
            error_msg = str(e.exceptions[0])
        else:
            error_msg = str(e)
        return RedirectResponse(
            f"/marketplace?error=connection_failed&message={error_msg}", status_code=302
        )
