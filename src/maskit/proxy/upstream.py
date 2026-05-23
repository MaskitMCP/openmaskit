"""Upstream transport: connection to the real MCP server."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING, TextIO

import httpx

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from maskit.models import UpstreamHttpConfig, UpstreamStdioConfig
from maskit.security import validate_server_id, read_token_file, write_token_file

if TYPE_CHECKING:
    from maskit.oauth.handler import OAuthCallbackServer

logger = logging.getLogger(__name__)


def _load_backend_oauth_token(server_id: str, store_path: str) -> str | None:
    """Load OAuth access token from backend-managed token file."""
    try:
        server_id = validate_server_id(server_id)
    except ValueError as e:
        logger.error(f"Invalid server_id for OAuth token: {e}")
        return None

    oauth_dir = Path(store_path).expanduser().parent / "oauth"
    token_path = oauth_dir / f"{server_id}.json"

    data = read_token_file(token_path)  # Handles decryption + migration
    return data.get("tokens", {}).get("access_token")


def _load_backend_oauth_tokens(server_id: str, store_path: str) -> dict | None:
    """Load OAuth tokens (access + refresh) from backend-managed token file.

    Returns dict with 'access_token', 'refresh_token', etc. or None.
    """
    try:
        server_id = validate_server_id(server_id)
    except ValueError as e:
        logger.error(f"Invalid server_id for OAuth token: {e}")
        return None

    oauth_dir = Path(store_path).expanduser().parent / "oauth"
    token_path = oauth_dir / f"{server_id}.json"

    data = read_token_file(token_path)  # Handles decryption + migration
    return data.get("tokens", {})


def _save_backend_oauth_tokens(server_id: str, store_path: str, tokens: dict) -> None:
    """Save refreshed OAuth tokens back to backend-managed token file."""
    try:
        server_id = validate_server_id(server_id)
    except ValueError as e:
        logger.error(f"Invalid server_id for OAuth token: {e}")
        return

    oauth_dir = Path(store_path).expanduser().parent / "oauth"
    oauth_dir.mkdir(parents=True, exist_ok=True)
    token_path = oauth_dir / f"{server_id}.json"

    # Read existing data to preserve other fields
    data = read_token_file(token_path) or {}
    data["tokens"] = tokens

    write_token_file(token_path, data)  # Handles encryption
    logger.info(f"Saved refreshed OAuth tokens for {server_id}")


async def refresh_backend_oauth_token(
    server_id: str,
    store_path: str,
    backend_client: Any,  # BackendClient type
) -> str | None:
    """Attempt to refresh expired OAuth token using backend API.

    Returns new access_token if successful, None otherwise.
    """
    # Load current tokens (need refresh_token)
    tokens = _load_backend_oauth_tokens(server_id, store_path)
    if not tokens or not tokens.get("refresh_token"):
        logger.warning(f"No refresh token available for {server_id}")
        return None

    refresh_token = tokens["refresh_token"]
    logger.info(f"Attempting to refresh OAuth token for {server_id}")

    # Call backend refresh API
    new_tokens = await backend_client.refresh_oauth_token(server_id, refresh_token)
    if not new_tokens or not new_tokens.get("access_token"):
        logger.error(f"Token refresh failed for {server_id}")
        return None

    # Save new tokens
    _save_backend_oauth_tokens(server_id, store_path, new_tokens)

    logger.info(f"Successfully refreshed OAuth token for {server_id}")
    return new_tokens["access_token"]


@asynccontextmanager
async def connect_upstream(
    upstream: UpstreamStdioConfig | UpstreamHttpConfig,
    store_path: str = "~/.maskit/store.db",
    errlog: TextIO = sys.stderr,
    extra_env: dict[str, str] | None = None,
    server_id: str | None = None,
    callback_server: "OAuthCallbackServer | None" = None,
):
    """Connect to the upstream MCP server. Yields (read_stream, write_stream)."""
    if isinstance(upstream, UpstreamStdioConfig):
        env = dict(upstream.env) if upstream.env else {}
        if extra_env:
            env.update(extra_env)

        params = StdioServerParameters(
            command=upstream.command,
            args=upstream.args,
            env=env if env else None,
        )
        async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
            yield read_stream, write_stream

    elif isinstance(upstream, UpstreamHttpConfig):
        # Check if there's a backend-managed OAuth token first
        access_token = None
        if upstream.oauth and server_id:
            access_token = _load_backend_oauth_token(server_id, store_path)

        if access_token:
            # Backend-managed OAuth: use simple Bearer token auth
            logger.info(f"Using backend-managed OAuth token for {server_id}")
            headers = {"Authorization": f"Bearer {access_token}"}
            http_client = httpx.AsyncClient(headers=headers, follow_redirects=True)
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream

        elif upstream.oauth:
            # Self-managed OAuth: use OAuth provider (original behavior for local servers)
            from maskit.oauth.handler import create_oauth_provider

            oauth_dir = Path(store_path).expanduser().parent / "oauth"
            oauth_dir.mkdir(parents=True, exist_ok=True)
            name = server_id or upstream.url.replace("https://", "").replace("/", "_")
            if server_id:
                try:
                    name = validate_server_id(name)
                except ValueError:
                    # Fallback to sanitized URL-based name
                    name = upstream.url.replace("https://", "").replace("/", "_")[:64].lower()
            oauth_store_path = oauth_dir / f"{name}.json"

            provider = await create_oauth_provider(
                upstream.url,
                upstream.oauth,
                oauth_store_path,
                callback_server=callback_server,
            )

            http_client = httpx.AsyncClient(auth=provider, follow_redirects=True)
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream

        else:
            # No OAuth: simple HTTP connection
            http_client = httpx.AsyncClient(follow_redirects=True)
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream

    else:
        raise ValueError(f"Unknown upstream config type: {type(upstream)}")
