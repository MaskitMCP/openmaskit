"""HTTP client for OpenMaskit backend services."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class BackendClient:
    """HTTP client for OpenMaskit backend services (marketplace + auth)."""

    def __init__(
        self,
        installation_id: str,
        openmaskit_version: str,
        auth_url: str | None = None,
        marketplace_url: str | None = None,
        timeout: float = 10.0,
    ):
        self.auth_url = auth_url or os.getenv(
            "OPENMASKIT_AUTH_BACKEND_URL", "https://auth.maskitmcp.com"
        )
        self.marketplace_url = marketplace_url or os.getenv(
            "OPENMASKIT_MARKETPLACE_API_URL", "https://api.maskitmcp.com"
        )
        self.client = httpx.AsyncClient(timeout=timeout)
        # OPENMASKIT_DISABLE_MARKETPLACE=1 opts out of all calls to
        # api.maskitmcp.com (catalog browse, server detail, version check).
        # Auth-side calls (exchange_code, refresh_oauth_token) keep working
        # so previously-installed hosted-broker servers can still refresh.
        self.enabled = os.getenv("OPENMASKIT_DISABLE_MARKETPLACE", "").strip() not in (
            "1", "true", "True", "yes",
        )
        self.installation_id = installation_id
        self.openmaskit_version = openmaskit_version
        self.required_headers = {
            'User-Agent': f"OpenMaskit/{self.openmaskit_version}",
            'X-OpenMaskit-Installation-Id': self.installation_id
        }

    async def close(self):
        """Close the HTTP client."""
        await self.client.aclose()

    # Marketplace API

    async def get_catalog(
        self, page: int = 1, size: int = 12, query: str | None = None
    ) -> dict[str, Any]:
        """Fetch marketplace catalog from backend.

        Args:
            page: Page number (1-indexed)
            size: Items per page
            query: Optional text search query

        Returns:
            Dict with 'data' (list of servers) and 'meta' (pagination info).
            Returns empty result on error: {"data": [], "meta": {"total": 0, "page": 1, "size": size, "total_pages": 0}}
        """
        if not self.marketplace_url or not self.enabled:
            return {"data": [], "meta": {"total": 0, "page": 1, "size": size, "total_pages": 0}}

        try:
            params = {"page": page, "size": size}
            if query:
                params["q"] = query

            resp = await self.client.get(
                f"{self.marketplace_url}/api/marketplace/catalog",
                params=params,
                headers=self.required_headers
            )
            resp.raise_for_status()
            response_data = resp.json()

            # Backend returns object with data and meta
            if isinstance(response_data, dict) and "data" in response_data and "meta" in response_data:
                return response_data
            else:
                logger.warning(f"Unexpected catalog response format: {type(response_data)}")
                return {"data": [], "meta": {"total": 0, "page": 1, "size": size, "total_pages": 0}}

        except Exception as e:
            logger.warning(f"Failed to fetch backend catalog: {e}")
            return {"data": [], "meta": {"total": 0, "page": 1, "size": size, "total_pages": 0}}

    async def check_version(self) -> dict[str, Any] | None:
        """Ask the marketplace backend whether this client version is supported.

        The current version travels in the User-Agent header (set in required_headers).
        Returns the parsed response body, or None on any failure (fail-open).
        """
        if not self.marketplace_url or not self.enabled:
            return None
        try:
            resp = await self.client.get(
                f"{self.marketplace_url}/api/version_check",
                headers=self.required_headers,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"version_check failed: {e}")
            return None

    async def get_server_info(self, server_id: str) -> dict[str, Any] | None:
        """Get server details by UUID.

        Returns None on error.
        """
        if not self.marketplace_url or not self.enabled:
            return None

        try:
            resp = await self.client.get(
                f"{self.marketplace_url}/api/marketplace/servers/{server_id}",
                headers=self.required_headers
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
        self, server_id: str, code: str
    ) -> dict[str, Any]:
        """Exchange authorization code for access token.

        Raises httpx.HTTPStatusError on failure.
        """
        resp = await self.client.post(
            f"{self.auth_url}/api/oauth/exchange",
            json={"server_id": server_id, "code": code},
        )
        resp.raise_for_status()
        return resp.json()

    async def refresh_oauth_token(
        self, server_id: str, refresh_token: str
    ) -> dict[str, Any] | None:
        """Refresh OAuth access token using refresh token.

        Args:
            server_id: Backend server UUID or handle
            refresh_token: Current refresh token

        Returns:
            New token dict with access_token, refresh_token, etc.
            Returns None if refresh fails.
        """
        try:
            resp = await self.client.post(
                f"{self.auth_url}/api/oauth/refresh",
                json={"server_id": server_id, "refresh_token": refresh_token},
            )
            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                logger.warning(
                    f"Refresh token expired for {server_id} - user must re-authenticate"
                )
            else:
                logger.error(f"Token refresh failed for {server_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Token refresh request failed for {server_id}: {e}")
            return None
