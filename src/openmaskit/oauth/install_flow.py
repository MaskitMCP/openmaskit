"""Install-time OAuth orchestration.

Owns the work that runs once when a user installs a BYO or DCR marketplace
server: AS metadata discovery, DCR (if needed), persisting ``client_info``,
generating PKCE + state, and assembling the authorize URL. The result is
handed to the marketplace install route which stashes it in
``app.state.oauth_states`` and returns the URL to the dashboard for a
same-tab redirect.

Runtime token refresh stays with the MCP SDK's ``OAuthClientProvider``
(see ``oauth/handler.py``); this module never touches running connections.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from mcp.shared.auth import OAuthClientInformationFull

from openmaskit import __version__ as openmaskit_version
from openmaskit.oauth import discovery
from openmaskit.oauth.authorize_url import build_authorize_url, generate_pkce
from openmaskit.oauth.handler import (
    OPENMASKIT_SOFTWARE_ID,
    FileTokenStorage,
    pick_dcr_token_endpoint_auth_method,
)

logger = logging.getLogger(__name__)


Mode = Literal["byo", "dcr"]


@dataclass(frozen=True, slots=True)
class InstallPrep:
    """Everything the callback handler needs to finish the install."""

    oauth_url: str
    state: str
    code_verifier: str
    token_endpoint: str
    client_id: str
    client_secret: str | None
    auth_method: str
    redirect_uri: str
    scope: str
    resource: str | None


async def _resolve_as_metadata(
    *, resolved_url: str, issuer: str | None
) -> dict:
    """Fetch authorization server metadata.

    When the caller already knows the issuer (DCR catalog entries that ship
    one), we fetch from it directly. Otherwise we run the spec-compliant
    discover flow against the MCP URL.
    """
    if issuer:
        metadata = await discovery.fetch_oauth_server_metadata(issuer)
        if not metadata:
            raise RuntimeError(
                f"Failed to fetch OAuth metadata for issuer {issuer}"
            )
        return metadata

    discovered = await discovery.discover(resolved_url)
    if not discovered:
        raise RuntimeError(
            "OAuth discovery failed; cannot determine authorization server"
        )
    return discovered


async def _ensure_dcr_client(
    *,
    storage: FileTokenStorage,
    metadata: dict,
    redirect_uri: str,
    scope: str,
    registration_token: str | None,
) -> tuple[str, str | None, str]:
    """Return ``(client_id, client_secret, auth_method)`` for DCR mode.

    Reuses an existing client_info on disk if present; otherwise registers
    a fresh client via RFC 7591 DCR and persists the result.
    """
    existing = await storage.get_client_info()
    if existing:
        secret = existing.client_secret
        method = existing.token_endpoint_auth_method or (
            "client_secret_post" if secret else "none"
        )
        return existing.client_id, secret, method

    registration_endpoint = metadata.get("registration_endpoint")
    if not registration_endpoint:
        raise RuntimeError(
            "DCR requested but authorization server does not support DCR "
            "(no registration_endpoint advertised)"
        )

    requested_auth_method = pick_dcr_token_endpoint_auth_method(
        metadata.get("token_endpoint_auth_methods_supported")
    )
    dcr_metadata: dict = {
        "client_name": "OpenMaskit",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": requested_auth_method,
        "software_id": OPENMASKIT_SOFTWARE_ID,
        "software_version": openmaskit_version,
    }
    if scope:
        dcr_metadata["scope"] = scope

    client_info_dict = await storage.register_dynamic_client(
        registration_endpoint, dcr_metadata, registration_token
    )

    client_id = client_info_dict["client_id"]
    client_secret = client_info_dict.get("client_secret")
    # RFC 7591 §3.2.1: AS MAY override the requested auth method.
    assigned_method = client_info_dict.get("token_endpoint_auth_method") or (
        "client_secret_post" if client_secret else "none"
    )

    client_info = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=client_secret,
        client_name="OpenMaskit",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=assigned_method,
    )
    await storage.set_client_info(client_info)
    await storage.set_registration_management(
        registration_access_token=client_info_dict.get("registration_access_token"),
        registration_client_uri=client_info_dict.get("registration_client_uri"),
    )
    logger.info(
        f"DCR registered client {client_id} (auth_method={assigned_method})"
    )
    return client_id, client_secret, assigned_method


async def _ensure_byo_client(
    *,
    storage: FileTokenStorage,
    client_id: str,
    client_secret: str | None,
    redirect_uri: str,
) -> str:
    """Persist user-supplied BYO credentials to FileTokenStorage.

    Returns the auth_method derived from the presence of ``client_secret``.
    Skips the write if storage already holds the same ``client_id`` to avoid
    redundant file I/O on reauthorize.
    """
    auth_method = "client_secret_post" if client_secret else "none"
    existing = await storage.get_client_info()
    if existing and existing.client_id == client_id:
        return existing.token_endpoint_auth_method or auth_method

    client_info = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=client_secret,
        client_name="OpenMaskit",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=auth_method,
    )
    await storage.set_client_info(client_info)
    return auth_method


async def prepare_oauth_install(
    *,
    resolved_url: str,
    mode: Mode,
    store_path: Path,
    base_url: str,
    handle: str,
    scope: str,
    client_id: str | None = None,
    client_secret: str | None = None,
    issuer: str | None = None,
    registration_token: str | None = None,
) -> InstallPrep:
    """Prepare a BYO or DCR install for a same-tab browser redirect.

    Resolves AS metadata, ensures we have a usable OAuth client (registering
    one for DCR mode when needed), generates state + PKCE, and returns the
    assembled authorize URL plus everything the callback handler needs to
    finish the flow.
    """
    metadata = await _resolve_as_metadata(
        resolved_url=resolved_url, issuer=issuer
    )

    auth_endpoint = metadata.get("authorization_endpoint")
    token_endpoint = metadata.get("token_endpoint")
    if not auth_endpoint or not token_endpoint:
        raise RuntimeError(
            "Authorization server metadata is missing authorization_endpoint "
            "or token_endpoint"
        )

    redirect_uri = f"{base_url.rstrip('/')}/oauth/callback/{handle}"
    storage = FileTokenStorage(store_path)

    if mode == "dcr":
        final_client_id, final_client_secret, auth_method = await _ensure_dcr_client(
            storage=storage,
            metadata=metadata,
            redirect_uri=redirect_uri,
            scope=scope,
            registration_token=registration_token,
        )
    else:
        if not client_id:
            raise RuntimeError("BYO install requires client_id")
        final_client_id = client_id
        final_client_secret = client_secret
        auth_method = await _ensure_byo_client(
            storage=storage,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    # RFC 8707 §2 resource indicator. When discovery surfaced a PRM with a
    # `resource`, we send it on both the authorize request and the token
    # exchange so the AS binds the token to the right resource server.
    # Without it, Slack-shaped providers (where the AS lives on a different
    # host from the MCP endpoint) issue tokens whose audience is the AS's
    # home and the MCP endpoint rejects the call.
    resource = metadata.get("resource") if metadata else None

    state = secrets.token_urlsafe(32)
    code_verifier, code_challenge = generate_pkce()
    oauth_url = build_authorize_url(
        auth_endpoint,
        client_id=final_client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        state=state,
        code_challenge=code_challenge,
        resource=resource,
    )

    return InstallPrep(
        oauth_url=oauth_url,
        state=state,
        code_verifier=code_verifier,
        token_endpoint=token_endpoint,
        client_id=final_client_id,
        client_secret=final_client_secret,
        auth_method=auth_method,
        redirect_uri=redirect_uri,
        scope=scope,
        resource=resource,
    )
