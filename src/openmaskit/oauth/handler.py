"""OAuth runtime support.

Install-time OAuth (discovery, DCR, building the authorize URL) lives in
``oauth/install_flow.py`` — that flow runs once when a marketplace server is
installed or reauthorized, persists tokens via :class:`FileTokenStorage`, and
hands off to the MCP SDK for runtime use.

This module owns the runtime half: building an ``OAuthClientProvider`` that
reads previously-persisted tokens, refreshes them on demand using the stored
``refresh_token``, and otherwise stays out of the way. The ``redirect_handler``
and ``callback_handler`` callbacks are stubbed to raise — if the SDK ever needs
a fresh authorization flow (tokens lost and refresh failed), we surface that as
a connection error so the user can hit Re-authorize in the dashboard, which
re-enters ``install_flow.prepare_oauth_install``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import httpx

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from openmaskit.models import HttpOAuthConfig
from openmaskit.oauth.discovery import issuer_matches, wellknown_metadata_urls
from openmaskit.security import TokenEncryption

logger = logging.getLogger(__name__)

# RFC 7591 §2 software_id — stable identifier for OpenMaskit as a product,
# the same across all installs and versions. AS admins can use it to
# identify (and, if necessary, throttle or block) OpenMaskit's DCR traffic.
OPENMASKIT_SOFTWARE_ID = "494c9118-2bf0-4897-aa6b-29d818ebf201"


class PinnedScopeClientMetadata(OAuthClientMetadata):
    """``OAuthClientMetadata`` whose ``scope`` cannot be overwritten once pinned.

    The MCP SDK's auth flow reassigns ``client_metadata.scope`` from PRM
    ``scopes_supported`` whenever it touches the 401 re-auth or 403
    ``insufficient_scope`` step-up paths (``mcp/client/auth/oauth2.py``, the two
    ``client_metadata.scope = get_client_metadata_scopes(...)`` call sites).

    For BYO installs whose OAuth client cannot grant every PRM-advertised scope
    (Atlassian's ``read:all:twg`` is the canonical example — only Atlassian-
    internal clients can request it), that reassignment converts a working
    runtime into a broken one. The operator's selected scope is the right
    answer; the SDK's spec-compliant strategy is the wrong one here.

    Silently ignore writes to ``scope`` once an initial non-empty value is set.
    Falsy initial scope (None / empty string) lets the SDK behave normally.
    """

    def __setattr__(self, name: str, value) -> None:
        if name == "scope" and getattr(self, "scope", None):
            logger.debug(
                "Ignoring SDK attempt to overwrite pinned scope %r with %r",
                self.scope,
                value,
            )
            return
        super().__setattr__(name, value)


def pick_dcr_token_endpoint_auth_method(supported: list[str] | None) -> str:
    """Pick the token_endpoint_auth_method to request in a DCR registration.

    Preserves byte-identical behaviour for every server that currently works:
    when the AS advertises `client_secret_post` (or doesn't advertise the
    field at all), we still send `client_secret_post`. Only when the AS
    explicitly excludes it do we negotiate down — preferring `none` (PKCE
    public client, the MCP authorization spec's recommended default) over
    `client_secret_basic` over whatever else the AS lists.
    """
    if not supported:
        return "client_secret_post"
    if "client_secret_post" in supported:
        return "client_secret_post"
    if "none" in supported:
        return "none"
    if "client_secret_basic" in supported:
        return "client_secret_basic"
    return supported[0]


class FileTokenStorage:
    """Persist OAuth tokens and client info to a JSON file."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._encryption = TokenEncryption()

    def _read(self) -> dict:
        """Read and decrypt token file."""
        if self._path.exists():
            try:
                ciphertext = self._path.read_text()
                plaintext = self._encryption.decrypt(ciphertext)
                data = json.loads(plaintext)

                # Auto-migrate plaintext
                if not ciphertext.startswith("ENCRYPTED:"):
                    logger.info(f"Migrating plaintext token file: {self._path}")
                    self._write(data)

                return data
            except (json.JSONDecodeError, OSError, Exception) as e:
                logger.warning(f"Failed to read token file: {e}")
        return {}

    def _write(self, data: dict):
        """Encrypt and write token file."""
        plaintext = json.dumps(data, indent=2, default=str)
        ciphertext = self._encryption.encrypt(plaintext)
        self._path.write_text(ciphertext)
        self._path.chmod(0o600)

    async def get_tokens(self) -> OAuthToken | None:
        data = self._read()
        raw = data.get("tokens")
        if raw:
            return OAuthToken.model_validate(raw)
        return None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        data = self._read()
        data["tokens"] = tokens.model_dump(exclude_none=True)
        self._write(data)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        data = self._read()
        raw = data.get("client_info")
        if raw:
            return OAuthClientInformationFull.model_validate(raw)
        return None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        data = self._read()
        data["client_info"] = client_info.model_dump(exclude_none=True)
        self._write(data)

    async def get_registration_management(self) -> dict | None:
        """RFC 7592 management metadata stored at DCR time, or None.

        Returns a dict with optional `registration_access_token` and
        `registration_client_uri` keys. A future de-register-on-uninstall
        flow uses these to call DELETE on the client configuration URI.
        """
        data = self._read()
        raw = data.get("registration_management")
        return raw if raw else None

    async def set_registration_management(
        self,
        registration_access_token: str | None,
        registration_client_uri: str | None,
    ) -> None:
        """Persist RFC 7592 management metadata returned in the DCR response."""
        if not registration_access_token and not registration_client_uri:
            return
        data = self._read()
        entry: dict = {}
        if registration_access_token:
            entry["registration_access_token"] = registration_access_token
        if registration_client_uri:
            entry["registration_client_uri"] = registration_client_uri
        data["registration_management"] = entry
        self._write(data)

    async def discover_oauth_metadata(self, issuer: str) -> dict | None:
        """Discover OAuth/OIDC authorization-server metadata for `issuer`.

        Used at runtime by `create_oauth_provider` solely to find the
        `registration_endpoint` for a fresh DCR. Install-time discovery
        (including the protected-resource step that can hop to a different
        host) is handled by `openmaskit.oauth.discovery`.
        """
        issuer = issuer.rstrip("/")
        oidc_metadata = None

        async with httpx.AsyncClient(timeout=10.0) as client:
            for oidc_url in wellknown_metadata_urls(issuer, "openid-configuration"):
                try:
                    logger.info(f"Attempting OIDC discovery at {oidc_url}")
                    resp = await client.get(oidc_url)
                    resp.raise_for_status()
                    candidate = resp.json()
                except Exception as e:
                    logger.debug(f"OIDC discovery failed at {oidc_url}: {e}")
                    continue
                if not issuer_matches(issuer, candidate.get("issuer")):
                    logger.warning(
                        f"OIDC metadata at {oidc_url} claims issuer "
                        f"{candidate.get('issuer')!r}, expected {issuer!r} "
                        "(RFC 8414 §3.3); skipping this candidate"
                    )
                    continue
                oidc_metadata = candidate
                break
            if oidc_metadata and oidc_metadata.get("registration_endpoint"):
                return oidc_metadata

            for oauth_url in wellknown_metadata_urls(issuer, "oauth-authorization-server"):
                try:
                    logger.info(f"Attempting OAuth 2.0 discovery at {oauth_url}")
                    resp = await client.get(oauth_url)
                    resp.raise_for_status()
                    oauth_metadata = resp.json()
                except Exception as e:
                    logger.debug(f"OAuth 2.0 discovery failed at {oauth_url}: {e}")
                    continue
                if not issuer_matches(issuer, oauth_metadata.get("issuer")):
                    logger.warning(
                        f"OAuth metadata at {oauth_url} claims issuer "
                        f"{oauth_metadata.get('issuer')!r}, expected {issuer!r} "
                        "(RFC 8414 §3.3); skipping this candidate"
                    )
                    continue
                if oidc_metadata:
                    merged = oidc_metadata.copy()
                    if oauth_metadata.get("registration_endpoint"):
                        merged["registration_endpoint"] = oauth_metadata["registration_endpoint"]
                    return merged
                return oauth_metadata

        if oidc_metadata:
            logger.info("Returning OIDC metadata (OAuth 2.0 discovery failed)")
            return oidc_metadata

        logger.error(f"All OAuth discovery methods failed for {issuer}")
        return None

    async def register_dynamic_client(
        self,
        registration_endpoint: str,
        client_metadata: dict,
        registration_token: str | None = None,
    ) -> dict:
        """Register OAuth client via DCR (RFC 7591).

        Returns the parsed client info on success. Raises RuntimeError on any
        failure, with the RFC 7591 §3.2.2 error / error_description fields
        included in the message when the server provided them, so callers
        (and the install UI) see a real diagnostic instead of a generic
        "DCR failed".
        """
        headers = {"Content-Type": "application/json"}
        if registration_token:
            headers["Authorization"] = f"Bearer {registration_token}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            logger.info(f"Attempting DCR at {registration_endpoint}")
            try:
                resp = await client.post(
                    registration_endpoint,
                    json=client_metadata,
                    headers=headers,
                )
            except httpx.HTTPError as e:
                msg = f"DCR network error at {registration_endpoint}: {e}"
                logger.error(msg)
                raise RuntimeError(msg) from e

            if 200 <= resp.status_code < 300:
                try:
                    result = resp.json()
                except ValueError as e:
                    raise RuntimeError(
                        f"DCR succeeded ({resp.status_code}) but response was not JSON: {e}"
                    ) from e
                logger.info(f"DCR successful, client_id: {result.get('client_id')}")
                return result

            # Non-2xx — try to surface the RFC 7591 §3.2.2 error fields.
            error_code: str | None = None
            error_description: str | None = None
            body_snippet = ""
            try:
                body = resp.json()
                if isinstance(body, dict):
                    error_code = body.get("error")
                    error_description = body.get("error_description")
            except ValueError:
                body_snippet = resp.text[:200].strip()

            parts = [f"DCR rejected by {registration_endpoint} ({resp.status_code}"]
            if error_code:
                parts[0] += f" {error_code})"
            else:
                parts[0] += ")"
            if error_description:
                parts.append(f": {error_description}")
            elif body_snippet:
                parts.append(f": {body_snippet}")

            msg = "".join(parts)
            logger.error(msg)
            raise RuntimeError(msg)


async def create_oauth_provider(
    server_url: str,
    oauth_config: HttpOAuthConfig,
    store_path: Path,
) -> OAuthClientProvider:
    """Create an OAuthClientProvider for runtime use.

    Reads ``client_info`` (and any tokens) that ``install_flow`` persisted at
    install or reauthorize time. Refresh works automatically via the stored
    ``refresh_token``. If a fresh authorization flow is ever needed at runtime
    — tokens lost AND refresh failed — the stub callbacks raise, surfacing the
    failure as a connection error so the user re-enters the flow through the
    dashboard's Re-authorize button.
    """
    storage = FileTokenStorage(store_path)

    existing_client_info = await storage.get_client_info()
    if not existing_client_info:
        raise RuntimeError(
            "No OAuth client_info on disk for this target. "
            "Install or reauthorize the server from the OpenMaskit dashboard."
        )

    scope = ""
    if oauth_config.scopes:
        scope = " ".join(oauth_config.scopes)
    elif oauth_config.scope:
        scope = oauth_config.scope

    auth_method = existing_client_info.token_endpoint_auth_method or (
        "client_secret_post" if existing_client_info.client_secret else "none"
    )
    stored_uris = (
        [str(u) for u in existing_client_info.redirect_uris]
        if existing_client_info.redirect_uris
        else []
    )

    client_metadata = PinnedScopeClientMetadata(
        client_name="OpenMaskit",
        redirect_uris=stored_uris,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method=auth_method,
        scope=scope,
    )

    async def redirect_handler(auth_url: str) -> None:
        raise RuntimeError(
            "Interactive OAuth flow is not supported at runtime — "
            "click Re-authorize in the OpenMaskit dashboard to refresh tokens."
        )

    async def callback_handler() -> tuple[str, str | None]:
        raise RuntimeError(
            "Interactive OAuth callback is not supported at runtime — "
            "click Re-authorize in the OpenMaskit dashboard."
        )

    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
