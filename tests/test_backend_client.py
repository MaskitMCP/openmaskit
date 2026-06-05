"""Tests for backend client."""

import pytest
import pytest_asyncio
import httpx
import respx

from openmaskit.backend_client import BackendClient


@pytest_asyncio.fixture
async def client():
    """Create backend client instance."""
    c = BackendClient(
        installation_id="test-install-123",
        openmaskit_version="0.1.0",
        auth_url="https://test-auth.example.com",
        marketplace_url="https://test-api.example.com",
        timeout=5.0,
    )
    yield c
    await c.close()


class TestBackendClientInit:
    """Test client initialization and configuration."""

    @pytest.mark.anyio
    async def test_init_with_explicit_urls(self):
        """Initialize client with explicit URLs."""
        client = BackendClient(
            installation_id="test-123",
            openmaskit_version="1.0.0",
            auth_url="https://custom-auth.com",
            marketplace_url="https://custom-api.com",
        )
        assert client.auth_url == "https://custom-auth.com"
        assert client.marketplace_url == "https://custom-api.com"
        assert client.installation_id == "test-123"
        assert client.openmaskit_version == "1.0.0"
        assert client.enabled is True
        await client.close()

    @pytest.mark.anyio
    async def test_init_with_env_vars(self, monkeypatch):
        """Initialize client with environment variables."""
        monkeypatch.setenv("OPENMASKIT_AUTH_BACKEND_URL", "https://env-auth.com")
        monkeypatch.setenv("OPENMASKIT_MARKETPLACE_API_URL", "https://env-api.com")

        client = BackendClient(
            installation_id="test-456",
            openmaskit_version="2.0.0",
        )
        assert client.auth_url == "https://env-auth.com"
        assert client.marketplace_url == "https://env-api.com"
        await client.close()

    @pytest.mark.anyio
    async def test_init_with_defaults(self, monkeypatch):
        """Initialize client with default URLs when no config provided."""
        monkeypatch.delenv("OPENMASKIT_AUTH_BACKEND_URL", raising=False)
        monkeypatch.delenv("OPENMASKIT_MARKETPLACE_API_URL", raising=False)

        client = BackendClient(
            installation_id="test-789",
            openmaskit_version="3.0.0",
        )
        assert client.auth_url == "https://auth.maskitmcp.com"
        assert client.marketplace_url == "https://api.maskitmcp.com"
        await client.close()

    @pytest.mark.anyio
    async def test_required_headers(self):
        """Verify required headers are set correctly."""
        client = BackendClient(
            installation_id="test-abc",
            openmaskit_version="4.5.6",
        )
        assert client.required_headers["User-Agent"] == "OpenMaskit/4.5.6"
        assert client.required_headers["X-OpenMaskit-Installation-Id"] == "test-abc"
        await client.close()

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", ["1", "true", "True", "yes"])
    async def test_disable_marketplace_env_var(self, monkeypatch, value):
        """OPENMASKIT_DISABLE_MARKETPLACE truthy values disable backend calls."""
        monkeypatch.setenv("OPENMASKIT_DISABLE_MARKETPLACE", value)
        client = BackendClient(installation_id="x", openmaskit_version="0.4.0")
        assert client.enabled is False
        await client.close()

    @pytest.mark.anyio
    @pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
    async def test_marketplace_enabled_by_default(self, monkeypatch, value):
        """Falsy/empty values keep marketplace enabled."""
        if value == "":
            monkeypatch.delenv("OPENMASKIT_DISABLE_MARKETPLACE", raising=False)
        else:
            monkeypatch.setenv("OPENMASKIT_DISABLE_MARKETPLACE", value)
        client = BackendClient(installation_id="x", openmaskit_version="0.4.0")
        assert client.enabled is True
        await client.close()

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_short_circuits_when_disabled(self, monkeypatch):
        """get_catalog returns empty result without making a request when disabled."""
        monkeypatch.setenv("OPENMASKIT_DISABLE_MARKETPLACE", "1")
        client = BackendClient(
            installation_id="x",
            openmaskit_version="0.4.0",
            marketplace_url="https://test-api.example.com",
        )
        # Intentionally do NOT register any respx route — if the client tries
        # to send a request, respx will raise.
        result = await client.get_catalog()
        assert result == {"data": [], "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0}}
        await client.close()

    @pytest.mark.anyio
    @respx.mock
    async def test_get_server_info_short_circuits_when_disabled(self, monkeypatch):
        """get_server_info returns None without making a request when disabled."""
        monkeypatch.setenv("OPENMASKIT_DISABLE_MARKETPLACE", "1")
        client = BackendClient(
            installation_id="x",
            openmaskit_version="0.4.0",
            marketplace_url="https://test-api.example.com",
        )
        result = await client.get_server_info("any-id")
        assert result is None
        await client.close()

    @pytest.mark.anyio
    @respx.mock
    async def test_check_version_short_circuits_when_disabled(self, monkeypatch):
        """check_version returns None without making a request when disabled."""
        monkeypatch.setenv("OPENMASKIT_DISABLE_MARKETPLACE", "1")
        client = BackendClient(
            installation_id="x",
            openmaskit_version="0.4.0",
            marketplace_url="https://test-api.example.com",
        )
        result = await client.check_version()
        assert result is None
        await client.close()


class TestMarketplaceCatalog:
    """Test marketplace catalog fetching."""

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_success(self, client):
        """Fetch catalog successfully."""
        catalog_data = {
            "data": [
                {
                    "id": "server-1",
                    "name": "Test Server 1",
                    "description": "A test server",
                    "icon_url": "https://example.com/icon1.png",
                },
                {
                    "id": "server-2",
                    "name": "Test Server 2",
                    "description": "Another test server",
                    "icon_url": "https://example.com/icon2.png",
                },
            ],
            "meta": {
                "total": 2,
                "page": 1,
                "size": 12,
                "total_pages": 1,
            },
        }

        respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(200, json=catalog_data)
        )

        result = await client.get_catalog()
        assert result == catalog_data
        assert len(result["data"]) == 2
        assert result["meta"]["total"] == 2

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_with_pagination(self, client):
        """Fetch catalog with pagination parameters."""
        route = respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [{"id": "s1"}],
                    "meta": {"total": 50, "page": 3, "size": 20, "total_pages": 3},
                },
            )
        )

        result = await client.get_catalog(page=3, size=20)
        assert result["meta"]["page"] == 3
        assert result["meta"]["size"] == 20

        # Verify request parameters
        request = route.calls.last.request
        assert request.url.params["page"] == "3"
        assert request.url.params["size"] == "20"

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_with_search_query(self, client):
        """Fetch catalog with search query."""
        route = respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [{"id": "github", "name": "GitHub"}],
                    "meta": {"total": 1, "page": 1, "size": 12, "total_pages": 1},
                },
            )
        )

        result = await client.get_catalog(query="github")
        assert len(result["data"]) == 1
        assert result["data"][0]["name"] == "GitHub"

        # Verify search param
        request = route.calls.last.request
        assert request.url.params["q"] == "github"

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_with_required_headers(self, client):
        """Verify required headers are sent with catalog request."""
        route = respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(
                200,
                json={"data": [], "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0}},
            )
        )

        await client.get_catalog()

        request = route.calls.last.request
        assert request.headers["User-Agent"] == "OpenMaskit/0.1.0"
        assert request.headers["X-OpenMaskit-Installation-Id"] == "test-install-123"

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_http_error(self, client):
        """Handle HTTP errors gracefully."""
        respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        result = await client.get_catalog()
        # Should return empty result on error
        assert result == {
            "data": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0},
        }

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_network_error(self, client):
        """Handle network errors gracefully."""
        respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            side_effect=httpx.ConnectError("Connection failed")
        )

        result = await client.get_catalog()
        # Should return empty result on network error
        assert result == {
            "data": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0},
        }

    @pytest.mark.anyio
    @respx.mock
    async def test_get_catalog_invalid_response_format(self, client):
        """Handle invalid response format."""
        respx.get("https://test-api.example.com/api/marketplace/catalog").mock(
            return_value=httpx.Response(200, json=["not", "expected", "format"])
        )

        result = await client.get_catalog()
        # Should return empty result for unexpected format
        assert result == {
            "data": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0},
        }

    @pytest.mark.anyio
    async def test_get_catalog_no_marketplace_url(self):
        """Return empty when marketplace URL is None."""
        client = BackendClient(
            installation_id="test",
            openmaskit_version="1.0.0",
            marketplace_url=None,
        )

        result = await client.get_catalog()
        assert result == {
            "data": [],
            "meta": {"total": 0, "page": 1, "size": 12, "total_pages": 0},
        }
        await client.close()


class TestServerInfo:
    """Test fetching server details."""

    @pytest.mark.anyio
    @respx.mock
    async def test_get_server_info_success(self, client):
        """Fetch server info successfully."""
        server_data = {
            "id": "test-server-uuid",
            "name": "Test Server",
            "description": "A test MCP server",
            "icon_url": "https://example.com/icon.png",
            "config": {"transport": "http", "url": "https://mcp.example.com"},
        }

        respx.get(
            "https://test-api.example.com/api/marketplace/servers/test-server-uuid"
        ).mock(return_value=httpx.Response(200, json=server_data))

        result = await client.get_server_info("test-server-uuid")
        assert result == server_data
        assert result["name"] == "Test Server"

    @pytest.mark.anyio
    @respx.mock
    async def test_get_server_info_not_found(self, client):
        """Handle 404 when server not found."""
        respx.get(
            "https://test-api.example.com/api/marketplace/servers/nonexistent"
        ).mock(return_value=httpx.Response(404, text="Not Found"))

        result = await client.get_server_info("nonexistent")
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_get_server_info_network_error(self, client):
        """Handle network errors."""
        respx.get(
            "https://test-api.example.com/api/marketplace/servers/test-id"
        ).mock(side_effect=httpx.TimeoutException("Request timeout"))

        result = await client.get_server_info("test-id")
        assert result is None

    @pytest.mark.anyio
    async def test_get_server_info_no_marketplace_url(self):
        """Return None when marketplace URL is not configured."""
        client = BackendClient(
            installation_id="test",
            openmaskit_version="1.0.0",
            marketplace_url=None,
        )

        result = await client.get_server_info("any-id")
        assert result is None
        await client.close()


class TestVersionCheck:
    """Test the version_check endpoint."""

    @pytest.mark.anyio
    @respx.mock
    async def test_check_version_supported(self, client):
        payload = {
            "supported": True,
            "update_required": False,
            "update_available": False,
            "latest_version": "0.1.0",
        }
        route = respx.get("https://test-api.example.com/api/version_check").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await client.check_version()
        assert result == payload
        # Version travels in User-Agent
        assert route.calls.last.request.headers["User-Agent"] == "OpenMaskit/0.1.0"
        assert route.calls.last.request.headers["X-OpenMaskit-Installation-Id"] == "test-install-123"

    @pytest.mark.anyio
    @respx.mock
    async def test_check_version_update_required(self, client):
        payload = {
            "supported": False,
            "update_required": True,
            "update_available": True,
            "latest_version": "0.5.0",
        }
        respx.get("https://test-api.example.com/api/version_check").mock(
            return_value=httpx.Response(200, json=payload)
        )
        result = await client.check_version()
        assert result["update_required"] is True

    @pytest.mark.anyio
    @respx.mock
    async def test_check_version_network_error_returns_none(self, client):
        respx.get("https://test-api.example.com/api/version_check").mock(
            side_effect=httpx.TimeoutException("boom")
        )
        result = await client.check_version()
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_check_version_http_error_returns_none(self, client):
        respx.get("https://test-api.example.com/api/version_check").mock(
            return_value=httpx.Response(500, text="internal")
        )
        result = await client.check_version()
        assert result is None


class TestOAuthAuthorizeURL:
    """Test OAuth authorization URL building."""

    @pytest.mark.anyio
    async def test_get_oauth_authorize_url(self, client):
        """Build OAuth authorization URL correctly."""
        url = client.get_oauth_authorize_url(
            server_id="github",
            state="random-state-123",
            redirect_uri="http://localhost:3131/callback",
        )

        assert url.startswith("https://test-auth.example.com/auth/authorize/github?")
        assert "state=random-state-123" in url
        assert "redirect_uri=http%3A%2F%2Flocalhost%3A3131%2Fcallback" in url

    @pytest.mark.anyio
    async def test_get_oauth_authorize_url_encoding(self, client):
        """Verify URL parameters are properly encoded."""
        url = client.get_oauth_authorize_url(
            server_id="slack",
            state="state with spaces & special=chars",
            redirect_uri="http://localhost:3131/callback?foo=bar",
        )

        # Should be URL-encoded
        assert "state+with+spaces" in url or "state%20with%20spaces" in url
        assert "%26" in url  # & encoded
        assert "%3D" in url  # = encoded


class TestOAuthCodeExchange:
    """Test OAuth code exchange."""

    @pytest.mark.anyio
    @respx.mock
    async def test_exchange_code_success(self, client):
        """Exchange authorization code successfully."""
        token_data = {
            "access_token": "eyJhbGc...",
            "refresh_token": "refresh_abc123",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        respx.post("https://test-auth.example.com/api/oauth/exchange").mock(
            return_value=httpx.Response(200, json=token_data)
        )

        result = await client.exchange_code(
            server_id="github",
            code="auth_code_xyz",
        )

        assert result == token_data
        assert result["access_token"] == "eyJhbGc..."
        assert result["refresh_token"] == "refresh_abc123"

    @pytest.mark.anyio
    @respx.mock
    async def test_exchange_code_invalid(self, client):
        """Handle invalid authorization code."""
        respx.post("https://test-auth.example.com/api/oauth/exchange").mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )

        with pytest.raises(httpx.HTTPStatusError):
            await client.exchange_code(
                server_id="github",
                code="invalid_code",
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_exchange_code_request_body(self, client):
        """Verify request body format."""
        route = respx.post("https://test-auth.example.com/api/oauth/exchange").mock(
            return_value=httpx.Response(200, json={"access_token": "token"})
        )

        await client.exchange_code(
            server_id="slack",
            code="code123",
        )

        request = route.calls.last.request
        body = request.content.decode()
        assert '"server_id":"slack"' in body or '"server_id": "slack"' in body
        assert '"code":"code123"' in body or '"code": "code123"' in body


class TestOAuthTokenRefresh:
    """Test OAuth token refresh."""

    @pytest.mark.anyio
    @respx.mock
    async def test_refresh_oauth_token_success(self, client):
        """Refresh token successfully."""
        new_token_data = {
            "access_token": "new_access_token",
            "refresh_token": "new_refresh_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        respx.post("https://test-auth.example.com/api/oauth/refresh").mock(
            return_value=httpx.Response(200, json=new_token_data)
        )

        result = await client.refresh_oauth_token(
            server_id="github",
            refresh_token="old_refresh_token",
        )

        assert result == new_token_data
        assert result["access_token"] == "new_access_token"
        assert result["refresh_token"] == "new_refresh_token"

    @pytest.mark.anyio
    @respx.mock
    async def test_refresh_oauth_token_expired(self, client):
        """Handle expired refresh token (401)."""
        respx.post("https://test-auth.example.com/api/oauth/refresh").mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )

        result = await client.refresh_oauth_token(
            server_id="github",
            refresh_token="expired_token",
        )

        # Should return None on 401
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_refresh_oauth_token_server_error(self, client):
        """Handle server errors during refresh."""
        respx.post("https://test-auth.example.com/api/oauth/refresh").mock(
            return_value=httpx.Response(500, text="Internal Server Error")
        )

        result = await client.refresh_oauth_token(
            server_id="slack",
            refresh_token="valid_token",
        )

        # Should return None on server error
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_refresh_oauth_token_network_error(self, client):
        """Handle network errors during refresh."""
        respx.post("https://test-auth.example.com/api/oauth/refresh").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = await client.refresh_oauth_token(
            server_id="github",
            refresh_token="token",
        )

        # Should return None on network error
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_refresh_oauth_token_request_body(self, client):
        """Verify request body format for token refresh."""
        route = respx.post("https://test-auth.example.com/api/oauth/refresh").mock(
            return_value=httpx.Response(200, json={"access_token": "new"})
        )

        await client.refresh_oauth_token(
            server_id="github",
            refresh_token="refresh_abc",
        )

        request = route.calls.last.request
        body = request.content.decode()
        assert '"server_id":"github"' in body or '"server_id": "github"' in body
        assert '"refresh_token":"refresh_abc"' in body or '"refresh_token": "refresh_abc"' in body


class TestClientLifecycle:
    """Test client lifecycle management."""

    @pytest.mark.anyio
    async def test_close_client(self):
        """Close client properly."""
        client = BackendClient(
            installation_id="test",
            openmaskit_version="1.0.0",
        )

        # Should not raise
        await client.close()

        # Client should be closed
        assert client.client.is_closed

    @pytest.mark.anyio
    async def test_client_as_context_manager(self):
        """Use client in async context (manual close)."""
        client = BackendClient(
            installation_id="test",
            openmaskit_version="1.0.0",
        )

        try:
            assert not client.client.is_closed
        finally:
            await client.close()
            assert client.client.is_closed
