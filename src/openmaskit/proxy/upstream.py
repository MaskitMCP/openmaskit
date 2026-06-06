"""Upstream transport: connection to the real MCP server."""

from __future__ import annotations

import json
import logging
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, TextIO

import anyio
import httpx

from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client

from openmaskit.models import UpstreamHttpConfig, UpstreamStdioConfig
from openmaskit.security import validate_server_id, read_token_file, write_token_file
from openmaskit.container import (
    OPENMASKIT_LABEL_KEY,
    OPENMASKIT_NAME_PREFIX,
    extract_container_name,
    get_container_runtime,
    has_rm_flag,
    inject_container_label,
    inject_container_name,
    is_container_run_command,
    preprocess_container_command,
    stop_container,
    sweep_server_orphans,
)

logger = logging.getLogger(__name__)


def _is_self_managed_oauth(server_id: str, store_path: str) -> bool:
    """True if the token file was written by the self-managed OAuth flow (DCR or
    manual client). Such files contain a `client_info` block; the backend-managed
    flow only writes `tokens`. Self-managed tokens must be refreshed by
    OAuthClientProvider talking directly to the provider, not via the backend.
    """
    try:
        server_id = validate_server_id(server_id)
    except ValueError:
        return False
    oauth_dir = Path(store_path).expanduser().parent / "oauth"
    token_path = oauth_dir / f"{server_id}.json"
    data = read_token_file(token_path)
    return bool(data.get("client_info"))


def _load_backend_oauth_token(server_id: str, store_path: str) -> str | None:
    """Load OAuth access token from backend-managed token file.

    Returns None for self-managed token files so connect_upstream falls through
    to the OAuthClientProvider path (which handles refresh against the provider).
    """
    try:
        server_id = validate_server_id(server_id)
    except ValueError as e:
        logger.error(f"Invalid server_id for OAuth token: {e}")
        return None

    oauth_dir = Path(store_path).expanduser().parent / "oauth"
    token_path = oauth_dir / f"{server_id}.json"

    data = read_token_file(token_path)  # Handles decryption + migration
    if data.get("client_info"):
        return None  # Self-managed; let OAuthClientProvider handle it
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
    import time
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
    tokens = dict(tokens)
    tokens.setdefault("created_at", time.time())
    data["tokens"] = tokens

    write_token_file(token_path, data)  # Handles encryption
    logger.info(f"Saved refreshed OAuth tokens for {server_id}")


def is_oauth_token_expired(server_id: str, store_path: str, skew_seconds: int = 60) -> bool:
    """Check if the stored OAuth token is expired (or near-expiry).

    Returns True if:
      - we can prove the token is past its lifetime minus skew, OR
      - the token file has a refresh_token but no created_at (legacy file written
        before created_at tracking; treat as unknown-age and refresh proactively).
    Returns False otherwise (no tokens, or no refresh_token to refresh with).
    """
    import time
    # Self-managed tokens (DCR / manual custom servers) are refreshed by the MCP
    # OAuthClientProvider talking to the provider directly. Don't pre-flight them.
    if _is_self_managed_oauth(server_id, store_path):
        return False
    tokens = _load_backend_oauth_tokens(server_id, store_path)
    if not tokens:
        return False
    if not tokens.get("refresh_token"):
        return False
    created_at = tokens.get("created_at")
    expires_in = tokens.get("expires_in")
    if not created_at or not expires_in:
        # Legacy token file — age unknown, refresh proactively.
        return True
    return (created_at + expires_in - skew_seconds) < time.time()


async def refresh_backend_oauth_token(
    server_id: str,
    store_path: str,
    backend_client: Any,  # BackendClient type
) -> str | None:
    """Attempt to refresh expired OAuth token using backend API.

    Only valid for backend-managed marketplace servers. Self-managed tokens
    (DCR / manual custom servers) refresh against the provider directly via
    OAuthClientProvider — calling the backend for those would be wrong.

    Returns new access_token if successful, None otherwise.
    """
    if _is_self_managed_oauth(server_id, store_path):
        logger.debug(f"{server_id} is self-managed OAuth; skipping backend refresh")
        return None
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
    store_path: str = "~/.openmaskit/store.db",
    errlog: TextIO = sys.stderr,
    extra_env: dict[str, str] | None = None,
    server_id: str | None = None,
    container_runtime: str | None = None,
):
    """
    Connect to the upstream MCP server.

    Yields ``(read_stream, write_stream, container_info)`` where
    ``container_info`` is ``(runtime, container_name)`` when the upstream is
    a containerized stdio command we manage, or ``None`` otherwise. Callers
    should stash ``container_info`` on the per-target state so an explicit
    ``stop_container`` can run on teardown without depending on this context
    manager's ``finally`` (which can be bypassed when the context is closed
    from a different task than the one that entered it).

    Args:
        container_runtime: Optional container runtime override (docker/podman/nerdctl/finch)
    """
    if isinstance(upstream, UpstreamStdioConfig):
        env = dict(upstream.env) if upstream.env else {}
        if extra_env:
            env.update(extra_env)

        # Preprocess command for container runtime substitution
        runtime = get_container_runtime(container_runtime)
        command, was_substituted = preprocess_container_command(upstream.command, runtime)

        if was_substituted:
            logger.debug(f"Substituted container command: {upstream.command} → {command}")

        # Container lifecycle management: when the upstream is a
        # `<runtime> run ...` command, inject a deterministic --name and
        # --label so we can stop it cleanly on context exit (and sweep
        # crash-orphans on next start).
        args = list(upstream.args)
        container_cleanup: tuple[str, str] | None = None
        if (
            runtime is not None
            and server_id
            and is_container_run_command(command, args)
        ):
            if not has_rm_flag(args):
                logger.warning(
                    "Container server '%s' is missing --rm; stopped containers "
                    "will accumulate and restart may fail with a name conflict. "
                    "Add --rm to args for automatic cleanup.",
                    server_id,
                )

            # Pre-start sweep: stop any crash-orphan with our label for this
            # server_id, so a stale `--name` doesn't block `docker run`.
            await sweep_server_orphans(runtime, server_id)

            container_name = (
                extract_container_name(args) or f"{OPENMASKIT_NAME_PREFIX}{server_id}"
            )
            args = inject_container_name(args, container_name)
            args = inject_container_label(args, OPENMASKIT_LABEL_KEY, server_id)
            container_cleanup = (runtime, container_name)

        params = StdioServerParameters(
            command=command,
            args=args,
            env=env if env else None,
        )
        try:
            async with stdio_client(params, errlog=errlog) as (read_stream, write_stream):
                yield read_stream, write_stream, container_cleanup
        finally:
            if container_cleanup is not None:
                rt, name = container_cleanup
                # Shield from outer cancellation so the stop call can finish.
                # stop_container has its own internal timeout, so it can't hang.
                with anyio.CancelScope(shield=True):
                    await stop_container(rt, name)

    elif isinstance(upstream, UpstreamHttpConfig):
        # Static request headers configured on the target (e.g. API-key auth
        # for non-OAuth servers like Datadog). These are merged into every
        # request the proxy makes upstream.
        static_headers = dict(upstream.headers or {})

        # Check if there's a backend-managed OAuth token first
        access_token = None
        if upstream.oauth and server_id:
            access_token = _load_backend_oauth_token(server_id, store_path)

        if access_token:
            # Backend-managed OAuth: use simple Bearer token auth
            logger.info(f"Using backend-managed OAuth token for {server_id}")
            headers = dict(static_headers)
            headers["Authorization"] = f"Bearer {access_token}"
            http_client = httpx.AsyncClient(headers=headers, follow_redirects=True)
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream, None

        elif upstream.oauth:
            # Self-managed OAuth: use OAuth provider (original behavior for local servers)
            from openmaskit.oauth.handler import create_oauth_provider

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
            )

            http_client = httpx.AsyncClient(
                auth=provider, headers=static_headers, follow_redirects=True
            )
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream, None

        else:
            # No OAuth: simple HTTP connection (optionally with static headers).
            http_client = httpx.AsyncClient(
                headers=static_headers, follow_redirects=True
            )
            async with http_client:
                async with streamable_http_client(
                    upstream.url, http_client=http_client
                ) as (read_stream, write_stream, _get_session_id):
                    yield read_stream, write_stream, None

    else:
        raise ValueError(f"Unknown upstream config type: {type(upstream)}")
