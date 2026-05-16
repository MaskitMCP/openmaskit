"""HTTP client for Maskit backend services."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BackendClient:
    """HTTP client for Maskit backend services (marketplace + auth)."""

    def __init__(
        self,
        auth_url: str | None = None,
        marketplace_url: str | None = None,
        timeout: float = 10.0,
    ):
        self.auth_url = auth_url or os.getenv(
            "MASKIT_AUTH_BACKEND_URL", "http://localhost:3134"
        )
        self.marketplace_url = marketplace_url or os.getenv(
            "MASKIT_MARKETPLACE_API_URL", "http://localhost:9800"
        )
        self.client = httpx.AsyncClient(timeout=timeout)
        # Always enabled (we have defaults for localhost)
        self.enabled = True

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    # Marketplace API

    async def get_catalog(self, page: int = 1, size: int = 100) -> list[dict[str, Any]]:
        """Fetch marketplace catalog from backend.

        Returns empty list on error (fallback to local catalog).
        """
        if not self.marketplace_url:
            return []

        try:
            resp = await self.client.get(
                f"{self.marketplace_url}/api/marketplace/catalog",
                params={"page": page, "size": size},
            )
            resp.raise_for_status()
            data = resp.json()
            # Backend returns array directly, not wrapped in {"servers": [...]}
            if isinstance(data, list):
                return data
            return []
        except Exception as e:
            logger.warning(f"Failed to fetch backend catalog: {e}")
            return []

    async def get_server_info(self, server_id: str) -> dict[str, Any] | None:
        """Get server details by UUID.

        Returns None on error.
        """
        if not self.marketplace_url:
            return None

        try:
            resp = await self.client.get(
                f"{self.marketplace_url}/api/marketplace/servers/{server_id}"
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"Failed to get server info for {server_id}: {e}")
            return None

    # OAuth API

    def get_oauth_authorize_url(
        self, server_id: str, state: str, redirect_uri: str
    ) -> str:
        """Build OAuth authorization URL."""
        from urllib.parse import urlencode

        params = urlencode({"state": state, "redirect_uri": redirect_uri})
        return f"{self.auth_url}/auth/authorize/{server_id}?{params}"

    async def exchange_code(
        self, server_id: str, code: str, redirect_uri: str
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Raises httpx.HTTPStatusError on failure.
        """
        resp = await self.client.post(
            f"{self.auth_url}/api/oauth/exchange",
            json={"server_id": server_id, "code": code, "redirect_uri": redirect_uri},
        )
        resp.raise_for_status()
        return resp.json()
