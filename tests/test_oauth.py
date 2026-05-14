"""Tests for OAuth handler and token storage."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest
from starlette.testclient import TestClient

from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from maskit.models import HttpOAuthConfig
from maskit.oauth.handler import FileTokenStorage, OAuthCallbackServer, create_oauth_provider


class TestFileTokenStorage:
    @pytest.mark.anyio
    async def test_file_token_storage_persists_tokens(self, tmp_path):
        """Tokens are written to and read from JSON file."""
        storage_path = tmp_path / "oauth" / "test.json"
        storage = FileTokenStorage(storage_path)

        token = OAuthToken(
            access_token="test-access-token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="test-refresh-token",
        )

        await storage.set_tokens(token)
        assert storage_path.exists()

        loaded = await storage.get_tokens()
        assert loaded is not None
        assert loaded.access_token == "test-access-token"
        assert loaded.refresh_token == "test-refresh-token"

    @pytest.mark.anyio
    async def test_file_token_storage_returns_none_when_empty(self, tmp_path):
        """Returns None when no tokens stored."""
        storage = FileTokenStorage(tmp_path / "empty.json")
        tokens = await storage.get_tokens()
        assert tokens is None

    @pytest.mark.anyio
    async def test_file_token_storage_creates_parent_directories(self, tmp_path):
        """Parent directories are created automatically."""
        storage_path = tmp_path / "deep" / "nested" / "path" / "oauth.json"
        storage = FileTokenStorage(storage_path)

        token = OAuthToken(access_token="test", token_type="Bearer")
        await storage.set_tokens(token)

        assert storage_path.exists()
        assert storage_path.parent.exists()

    @pytest.mark.anyio
    async def test_file_token_storage_overwrites_existing_tokens(self, tmp_path):
        """New tokens overwrite old ones."""
        storage = FileTokenStorage(tmp_path / "test.json")

        token1 = OAuthToken(access_token="old-token", token_type="Bearer")
        await storage.set_tokens(token1)

        token2 = OAuthToken(access_token="new-token", token_type="Bearer")
        await storage.set_tokens(token2)

        loaded = await storage.get_tokens()
        assert loaded.access_token == "new-token"

    @pytest.mark.anyio
    async def test_file_token_storage_persists_client_info(self, tmp_path):
        """Client info is persisted separately from tokens."""
        storage = FileTokenStorage(tmp_path / "test.json")

        client_info = OAuthClientInformationFull(
            client_id="test-client-id",
            client_secret="test-secret",
            client_name="Test Client",
            redirect_uris=["http://localhost:3131/callback"],
            grant_types=["authorization_code"],
            response_types=["code"],
        )

        await storage.set_client_info(client_info)

        loaded = await storage.get_client_info()
        assert loaded is not None
        assert loaded.client_id == "test-client-id"
        assert loaded.client_secret == "test-secret"

    @pytest.mark.anyio
    async def test_file_token_storage_handles_corrupted_json(self, tmp_path):
        """Gracefully handles corrupted JSON file."""
        storage_path = tmp_path / "corrupt.json"
        storage_path.write_text("{ invalid json }")

        storage = FileTokenStorage(storage_path)
        tokens = await storage.get_tokens()
        assert tokens is None

    @pytest.mark.anyio
    async def test_file_token_storage_tokens_and_client_info_coexist(self, tmp_path):
        """Both tokens and client info can be stored in same file."""
        storage = FileTokenStorage(tmp_path / "test.json")

        token = OAuthToken(access_token="token", token_type="Bearer")
        await storage.set_tokens(token)

        client_info = OAuthClientInformationFull(
            client_id="client-id",
            redirect_uris=["http://localhost/callback"],
        )
        await storage.set_client_info(client_info)

        # Both should be readable
        loaded_token = await storage.get_tokens()
        loaded_client = await storage.get_client_info()

        assert loaded_token.access_token == "token"
        assert loaded_client.client_id == "client-id"


class TestOAuthCallbackServer:
    @pytest.mark.anyio
    async def test_callback_server_receives_auth_code(self):
        """Callback route receives authorization code and state."""
        server = OAuthCallbackServer(port=3131)
        app = server.create_app()
        client = TestClient(app)

        async def make_callback():
            await anyio.sleep(0.1)
            response = client.get("/callback?code=test-code&state=test-state")
            assert response.status_code == 200

        async with anyio.create_task_group() as tg:
            tg.start_soon(make_callback)
            code, state = await server.wait_for_callback()

        assert code == "test-code"
        assert state == "test-state"

    @pytest.mark.anyio
    async def test_callback_server_handles_oauth_error(self):
        """Callback route handles OAuth error response."""
        server = OAuthCallbackServer(port=3131)
        app = server.create_app()
        client = TestClient(app)

        async def make_callback():
            await anyio.sleep(0.1)
            response = client.get("/callback?error=access_denied&error_description=User+denied")
            assert response.status_code == 400
            assert "Authentication Failed" in response.text

        async with anyio.create_task_group() as tg:
            tg.start_soon(make_callback)
            code, state = await server.wait_for_callback()

        assert code == ""
        assert state is None

    def test_callback_server_redirect_uri(self):
        """Redirect URI is correctly formatted."""
        server = OAuthCallbackServer(port=3131)
        assert server.redirect_uri == "http://localhost:3131/callback"

        server2 = OAuthCallbackServer(port=9999)
        assert server2.redirect_uri == "http://localhost:9999/callback"

    @pytest.mark.anyio
    async def test_callback_server_resets_state_between_flows(self):
        """State is reset for each new OAuth flow."""
        server = OAuthCallbackServer(port=3131)
        app = server.create_app()
        client = TestClient(app)

        # First flow
        async def first_callback():
            await anyio.sleep(0.05)
            client.get("/callback?code=code1&state=state1")

        async with anyio.create_task_group() as tg:
            tg.start_soon(first_callback)
            code1, state1 = await server.wait_for_callback()

        assert code1 == "code1"

        # Second flow
        async def second_callback():
            await anyio.sleep(0.05)
            client.get("/callback?code=code2&state=state2")

        async with anyio.create_task_group() as tg:
            tg.start_soon(second_callback)
            code2, state2 = await server.wait_for_callback()

        assert code2 == "code2"
        assert code2 != code1


class TestCreateOAuthProvider:
    @pytest.mark.anyio
    async def test_create_oauth_provider_with_client_id(self, tmp_path):
        """Provider created with pre-configured client ID."""
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(
            client_id="test-client-id",
            client_secret="test-secret",
            scope="read write",
        )

        provider = create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        assert provider is not None
        # Verify client info was pre-seeded
        storage = FileTokenStorage(tmp_path / "oauth.json")
        client_info = await storage.get_client_info()
        assert client_info is not None
        assert client_info.client_id == "test-client-id"

    @pytest.mark.anyio
    async def test_create_oauth_provider_without_client_id(self, tmp_path):
        """Provider created without client ID (DCR mode)."""
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(scope="read")

        provider = create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        assert provider is not None
        # No client info pre-seeded
        storage = FileTokenStorage(tmp_path / "oauth.json")
        client_info = await storage.get_client_info()
        assert client_info is None

    @pytest.mark.anyio
    async def test_create_oauth_provider_updates_changed_client_id(self, tmp_path):
        """Client info updated if client_id changes in config."""
        storage_path = tmp_path / "oauth.json"
        storage = FileTokenStorage(storage_path)

        # Pre-seed with old client ID
        old_client_info = OAuthClientInformationFull(
            client_id="old-id",
            redirect_uris=["http://localhost:3131/callback"],
        )
        await storage.set_client_info(old_client_info)

        # Create provider with new client ID
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(client_id="new-id")

        provider = create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=storage_path,
            callback_server=callback_server,
        )

        # Client info should be updated
        client_info = await storage.get_client_info()
        assert client_info.client_id == "new-id"

    @pytest.mark.anyio
    async def test_create_oauth_provider_with_client_secret(self, tmp_path):
        """Provider uses client_secret_post auth when secret provided."""
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(
            client_id="test-id",
            client_secret="test-secret",
        )

        provider = create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        storage = FileTokenStorage(tmp_path / "oauth.json")
        client_info = await storage.get_client_info()
        assert client_info.token_endpoint_auth_method == "client_secret_post"

    @pytest.mark.anyio
    async def test_create_oauth_provider_without_client_secret(self, tmp_path):
        """Provider uses 'none' auth when no secret provided."""
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(client_id="test-id")

        provider = create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        storage = FileTokenStorage(tmp_path / "oauth.json")
        client_info = await storage.get_client_info()
        assert client_info.token_endpoint_auth_method == "none"
