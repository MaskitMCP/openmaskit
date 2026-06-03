"""OAuth support using the MCP SDK's built-in OAuthClientProvider.

This implements the TokenStorage protocol and provides the redirect/callback
handlers that OAuthClientProvider needs to drive the browser-based OAuth flow.
"""

from __future__ import annotations

import json
import logging
import sys
import webbrowser
from pathlib import Path

import anyio
import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from openmaskit.models import HttpOAuthConfig
from openmaskit.oauth.discovery import issuer_matches, wellknown_metadata_urls
from openmaskit.oauth.sdk_patches import register_scope_override
from openmaskit.security import TokenEncryption

logger = logging.getLogger(__name__)

OAUTH_CALLBACK_PORT = 3131


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


class OAuthCallbackServer:
    """Always-on HTTP server that receives OAuth callbacks for all targets."""

    def __init__(self, port: int = OAUTH_CALLBACK_PORT):
        self._port = port
        self._auth_code: str | None = None
        self._state: str | None = None
        self._event = anyio.Event()

    @property
    def redirect_uri(self) -> str:
        return f"http://localhost:{self._port}/callback"

    async def _callback_route(self, request: Request):
        self._auth_code = request.query_params.get("code")
        self._state = request.query_params.get("state")
        error = request.query_params.get("error")

        if error:
            self._event.set()
            return HTMLResponse(
                f"<h1>Authentication Failed</h1><p>{error}</p>", status_code=400
            )

        self._event.set()
        return HTMLResponse(
            "<html><head>"
            "<meta http-equiv='refresh' content='3;url=http://localhost:9473/'>"
            "</head><body style='background:#0f1117;color:#e1e4e8;font-family:sans-serif;"
            "display:flex;align-items:center;justify-content:center;height:100vh;'>"
            "<div style='text-align:center'>"
            "<h1 style='color:#3fb950'>&#10003; Authenticated</h1>"
            "<p>Redirecting to OpenMaskit in <span id='countdown'>3</span> seconds...</p>"
            "<p style='margin-top:20px'>"
            "<a href='http://localhost:9473/' style='color:#2dd4bf;text-decoration:none;border:1px solid #2dd4bf;padding:8px 16px;border-radius:4px;display:inline-block;'>"
            "Click here to go now"
            "</a>"
            "</p>"
            "</div>"
            "<script>"
            "let count = 3;"
            "setInterval(() => {"
            "  count--;"
            "  if (count >= 0) document.getElementById('countdown').textContent = count;"
            "}, 1000);"
            "</script>"
            "</body></html>"
        )

    def create_app(self) -> Starlette:
        return Starlette(routes=[
            Route("/callback", self._callback_route),
        ])

    async def wait_for_callback(self) -> tuple[str, str | None]:
        """Wait for the next OAuth callback. Resets state for each new flow."""
        self._event = anyio.Event()
        self._auth_code = None
        self._state = None
        await self._event.wait()
        return self._auth_code or "", self._state


async def create_oauth_provider(
    server_url: str,
    oauth_config: HttpOAuthConfig,
    store_path: Path,
    callback_server: OAuthCallbackServer,
) -> OAuthClientProvider:
    """Create an OAuthClientProvider configured for the given MCP server.

    If oauth_config has issuer (DCR mode), performs OAuth discovery and DCR.
    If oauth_config has a client_id (manual mode), pre-seeds storage to skip DCR.
    """

    storage = FileTokenStorage(store_path)
    redirect_uri = callback_server.redirect_uri

    # DCR mode: issuer provided
    if oauth_config.issuer:
        logger.info(f"DCR mode: discovering OAuth metadata for issuer {oauth_config.issuer}")

        metadata = await storage.discover_oauth_metadata(oauth_config.issuer)
        if not metadata:
            raise RuntimeError(f"Failed to discover OAuth metadata for issuer: {oauth_config.issuer}")

        # Prepare scope
        scope = " ".join(oauth_config.scopes) if oauth_config.scopes else ""

        # Check if we already have DCR-registered client info
        existing_client_info = await storage.get_client_info()

        if existing_client_info:
            logger.info("Using existing DCR client from storage")
            auth_method = "none"
            if existing_client_info.client_secret:
                auth_method = "client_secret_post"

            client_metadata = OAuthClientMetadata(
                client_name="OpenMaskit",
                redirect_uris=[redirect_uri],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method=auth_method,
                scope=scope,
            )
        else:
            # Perform DCR if registration_endpoint available
            registration_endpoint = metadata.get("registration_endpoint")
            if not registration_endpoint:
                raise RuntimeError(f"DCR requested but issuer {oauth_config.issuer} does not support DCR (no registration_endpoint)")

            requested_auth_method = pick_dcr_token_endpoint_auth_method(
                metadata.get("token_endpoint_auth_methods_supported")
            )
            dcr_metadata = {
                "client_name": "OpenMaskit",
                "redirect_uris": [redirect_uri],
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "token_endpoint_auth_method": requested_auth_method,
            }
            if scope:
                dcr_metadata["scope"] = scope

            # register_dynamic_client raises with the AS's
            # error_description on any failure, so we don't need a generic
            # "DCR failed" wrapper here.
            client_info_dict = await storage.register_dynamic_client(
                registration_endpoint,
                dcr_metadata,
                oauth_config.registration_token,
            )

            # RFC 7591 §3.2.1: the AS MAY override what we requested in
            # `token_endpoint_auth_method` (Stripe registers as `none` even
            # if we asked for `client_secret_post`). Trust the AS's response
            # field; fall back to inferring from secret presence for ASes
            # that omit it.
            assigned_auth_method = client_info_dict.get("token_endpoint_auth_method")
            if not assigned_auth_method:
                assigned_auth_method = (
                    "client_secret_post"
                    if client_info_dict.get("client_secret")
                    else "none"
                )

            # Store the DCR result
            client_info = OAuthClientInformationFull(
                client_id=client_info_dict["client_id"],
                client_secret=client_info_dict.get("client_secret"),
                client_name="OpenMaskit",
                redirect_uris=[redirect_uri],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method=assigned_auth_method,
            )
            await storage.set_client_info(client_info)
            logger.info(
                f"Stored DCR client info: {client_info.client_id} "
                f"(auth_method={assigned_auth_method})"
            )

            auth_method = assigned_auth_method

            client_metadata = OAuthClientMetadata(
                client_name="OpenMaskit",
                redirect_uris=[redirect_uri],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method=auth_method,
                scope=scope,
            )

    # Manual mode: client_id provided
    else:
        logger.info(f"Manual mode: using provided client_id {oauth_config.client_id}")

        auth_method = "none"
        if oauth_config.client_secret:
            auth_method = "client_secret_post"

        # Prepare scope
        scope = oauth_config.scope or ""

        client_metadata = OAuthClientMetadata(
            client_name="OpenMaskit",
            redirect_uris=[redirect_uri],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method=auth_method,
            scope=scope,
        )

        if oauth_config.client_id:
            existing_client_info = await storage.get_client_info()
            stored_id = existing_client_info.client_id if existing_client_info else None
            if stored_id != oauth_config.client_id:
                client_info = OAuthClientInformationFull(
                    client_id=oauth_config.client_id,
                    client_secret=oauth_config.client_secret,
                    client_name="OpenMaskit",
                    redirect_uris=[redirect_uri],
                    grant_types=["authorization_code", "refresh_token"],
                    response_types=["code"],
                    token_endpoint_auth_method=auth_method,
                )
                await storage.set_client_info(client_info)

    async def redirect_handler(auth_url: str) -> None:
        print(
            f"\n  Opening browser for authentication...\n"
            f"  If it doesn't open, visit:\n  {auth_url}\n",
            file=sys.stderr,
        )
        webbrowser.open(auth_url)

    async def callback_handler() -> tuple[str, str | None]:
        return await callback_server.wait_for_callback()

    # Pin the user-selected scope so the SDK's spec-compliant strategy
    # (which would otherwise overwrite it with PRM scopes_supported) returns
    # what the operator actually chose. See oauth/sdk_patches.py.
    register_scope_override(client_metadata, scope)

    # Always use the full server_url - the MCP SDK handles OAuth discovery internally
    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    return provider
