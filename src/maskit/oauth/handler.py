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
from urllib.parse import parse_qs, urlparse

import anyio
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse
from starlette.routing import Route

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from maskit.models import HttpOAuthConfig

logger = logging.getLogger(__name__)


class FileTokenStorage:
    """Persist OAuth tokens and client info to a JSON file."""

    def __init__(self, path: Path):
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def _read(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {}

    def _write(self, data: dict):
        self._path.write_text(json.dumps(data, indent=2, default=str))

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


class OAuthCallbackServer:
    """Tiny HTTP server that receives the OAuth callback."""

    def __init__(self, port: int):
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
            "<html><body style='background:#0f1117;color:#e1e4e8;font-family:sans-serif;"
            "display:flex;align-items:center;justify-content:center;height:100vh;'>"
            "<div style='text-align:center'>"
            "<h1 style='color:#3fb950'>&#10003; Authenticated</h1>"
            "<p>You can close this tab. Maskit is connecting...</p>"
            "</div></body></html>"
        )

    def create_app(self) -> Starlette:
        return Starlette(routes=[
            Route("/callback", self._callback_route),
        ])

    async def wait_for_callback(self) -> tuple[str, str | None]:
        """Wait for the OAuth callback and return (code, state)."""
        await self._event.wait()
        return self._auth_code or "", self._state


def create_oauth_provider(
    server_url: str,
    oauth_config: HttpOAuthConfig,
    store_path: Path,
) -> tuple[OAuthClientProvider, OAuthCallbackServer]:
    """Create an OAuthClientProvider configured for the given MCP server."""

    callback_server = OAuthCallbackServer(oauth_config.callback_port)
    storage = FileTokenStorage(store_path)

    redirect_uri = callback_server.redirect_uri

    client_metadata = OAuthClientMetadata(
        client_name="Maskit",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )

    # Pre-seed storage with the configured client_id to skip dynamic registration
    # (many servers like Slack don't support dynamic client registration)
    data = storage._read()
    if not data.get("client_info") or data["client_info"].get("client_id") != oauth_config.client_id:
        client_info = OAuthClientInformationFull(
            client_id=oauth_config.client_id,
            client_name="Maskit",
            redirect_uris=[redirect_uri],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="none",
        )
        data["client_info"] = client_info.model_dump(exclude_none=True)
        storage._write(data)

    async def redirect_handler(auth_url: str) -> None:
        print(
            f"\n  Opening browser for authentication...\n"
            f"  If it doesn't open, visit:\n  {auth_url}\n",
            file=sys.stderr,
        )
        webbrowser.open(auth_url)

    async def callback_handler() -> tuple[str, str | None]:
        return await callback_server.wait_for_callback()

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )

    return provider, callback_server
