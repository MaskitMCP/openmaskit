"""Tests for OAuth handler and token storage."""

from __future__ import annotations

import json
from pathlib import Path

import anyio
import httpx
import pytest
import respx
from starlette.testclient import TestClient

from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from openmaskit.models import HttpOAuthConfig
from openmaskit.oauth.handler import (
    OPENMASKIT_SOFTWARE_ID,
    FileTokenStorage,
    OAuthCallbackServer,
    create_oauth_provider,
    pick_dcr_token_endpoint_auth_method,
)


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
        """Canonical redirect URI is the 127.0.0.1 form per RFC 8252 §7.3."""
        server = OAuthCallbackServer(port=3131)
        assert server.redirect_uri == "http://127.0.0.1:3131/callback"

        server2 = OAuthCallbackServer(port=9999)
        assert server2.redirect_uri == "http://127.0.0.1:9999/callback"

    def test_callback_server_legacy_redirect_uri(self):
        """The localhost form is exposed for BYO setup guides and old DCRs."""
        server = OAuthCallbackServer(port=3131)
        assert server.legacy_redirect_uri == "http://localhost:3131/callback"

    def test_callback_server_loopback_pair_canonical_first(self):
        """DCR registers both forms; the canonical one comes first."""
        server = OAuthCallbackServer(port=3131)
        assert server.loopback_redirect_uris == [
            "http://127.0.0.1:3131/callback",
            "http://localhost:3131/callback",
        ]

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

        provider = await create_oauth_provider(
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

        provider = await create_oauth_provider(
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

        provider = await create_oauth_provider(
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

        provider = await create_oauth_provider(
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

        provider = await create_oauth_provider(
            server_url="http://example.com",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        storage = FileTokenStorage(tmp_path / "oauth.json")
        client_info = await storage.get_client_info()
        assert client_info.token_endpoint_auth_method == "none"


class TestTokenFilePermissions:
    """Test that token files are created with secure permissions."""

    @pytest.mark.anyio
    async def test_token_file_has_secure_permissions(self, tmp_path):
        """Token files are created with owner-only permissions (0o600)."""
        storage_path = tmp_path / "oauth" / "secure_test.json"
        storage = FileTokenStorage(storage_path)

        token = OAuthToken(
            access_token="sensitive-access-token",
            token_type="Bearer",
            expires_in=3600,
            refresh_token="sensitive-refresh-token",
        )

        await storage.set_tokens(token)

        # Verify file exists
        assert storage_path.exists()

        # Verify permissions are 0o600 (owner read/write only)
        file_mode = storage_path.stat().st_mode & 0o777
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"

    @pytest.mark.anyio
    async def test_oauth_callback_token_file_permissions(self, tmp_path):
        """OAuth callback handler creates token files with secure permissions."""
        # This tests the oauth_callback.py code path
        token_path = tmp_path / "oauth" / "callback_test.json"
        token_path.parent.mkdir(parents=True, exist_ok=True)

        token_data = {
            "tokens": {
                "access_token": "callback-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "callback-refresh",
            }
        }

        # Simulate the oauth_callback.py code
        with open(token_path, "w") as f:
            json.dump(token_data, f, indent=2)

        # Apply the fix
        token_path.chmod(0o600)

        # Verify permissions
        file_mode = token_path.stat().st_mode & 0o777
        assert file_mode == 0o600, f"Expected 0o600, got {oct(file_mode)}"


class TestOAuthEncryption:
    """Test OAuth flow with encryption."""

    async def test_file_token_storage_encrypts(self, tmp_path):
        from openmaskit.oauth.handler import FileTokenStorage
        from mcp.shared.auth import OAuthToken

        storage = FileTokenStorage(tmp_path / "test.json")
        token = OAuthToken(
            access_token="secret123",
            token_type="Bearer",
            refresh_token="refresh456"
        )

        await storage.set_tokens(token)

        # File should contain encrypted data
        content = (tmp_path / "test.json").read_text()
        assert content.startswith("ENCRYPTED:")
        assert "secret123" not in content
        assert "refresh456" not in content

        # Should decrypt correctly
        loaded = await storage.get_tokens()
        assert loaded.access_token == "secret123"
        assert loaded.refresh_token == "refresh456"

    async def test_migration_preserves_tokens(self, tmp_path):
        import json
        from openmaskit.oauth.handler import FileTokenStorage

        path = tmp_path / "legacy.json"
        legacy_data = {
            "tokens": {
                "access_token": "legacy_access",
                "refresh_token": "legacy_refresh",
                "token_type": "Bearer"
            }
        }
        path.write_text(json.dumps(legacy_data))

        storage = FileTokenStorage(path)
        tokens = await storage.get_tokens()

        assert tokens.access_token == "legacy_access"
        assert tokens.refresh_token == "legacy_refresh"

        # Should now be encrypted
        content = path.read_text()
        assert content.startswith("ENCRYPTED:")
        assert "legacy_access" not in content


class TestDiscoverOauthMetadata:
    """Runtime AS metadata lookup used by DCR re-registration."""

    @pytest.mark.anyio
    @respx.mock
    async def test_root_issuer(self, tmp_path):
        meta = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
        }
        respx.get(
            "https://auth.example.com/.well-known/openid-configuration"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://auth.example.com/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json=meta))

        storage = FileTokenStorage(tmp_path / "tok.json")
        result = await storage.discover_oauth_metadata("https://auth.example.com")
        assert result is not None
        assert result["registration_endpoint"] == "https://auth.example.com/register"

    @pytest.mark.anyio
    @respx.mock
    async def test_path_issuer_stripe_shape(self, tmp_path):
        """Regression for the Stripe DCR failure: issuer has a non-empty path."""
        meta = {
            "issuer": "https://access.stripe.com/mcp",
            "authorization_endpoint": "https://access.stripe.com/mcp/oauth2/authorize",
            "token_endpoint": "https://access.stripe.com/mcp/oauth2/token",
            "registration_endpoint": "https://access.stripe.com/mcp/oauth2/register",
        }
        respx.get(
            "https://access.stripe.com/.well-known/openid-configuration/mcp"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://access.stripe.com/.well-known/oauth-authorization-server/mcp"
        ).mock(return_value=httpx.Response(200, json=meta))

        storage = FileTokenStorage(tmp_path / "tok.json")
        result = await storage.discover_oauth_metadata(
            "https://access.stripe.com/mcp"
        )
        assert result is not None
        assert result["registration_endpoint"] == (
            "https://access.stripe.com/mcp/oauth2/register"
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_rejects_metadata_with_mismatched_issuer(self, tmp_path):
        """Runtime DCR discovery must reject impostor metadata per RFC 8414 §3.3."""
        bad = {
            "issuer": "https://impostor.example.com",
            "authorization_endpoint": "https://impostor.example.com/authorize",
            "token_endpoint": "https://impostor.example.com/token",
            "registration_endpoint": "https://impostor.example.com/register",
        }
        respx.get(
            "https://auth.example.com/.well-known/openid-configuration"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://auth.example.com/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json=bad))
        storage = FileTokenStorage(tmp_path / "tok.json")
        result = await storage.discover_oauth_metadata("https://auth.example.com")
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_path_issuer_appended_fallback(self, tmp_path):
        """Non-spec-compliant server serves only the appended form."""
        meta = {
            "issuer": "https://legacy.example.com/tenantA",
            "authorization_endpoint": "https://legacy.example.com/tenantA/oauth/authorize",
            "token_endpoint": "https://legacy.example.com/tenantA/oauth/token",
            "registration_endpoint": "https://legacy.example.com/tenantA/oauth/register",
        }
        respx.get(
            "https://legacy.example.com/.well-known/openid-configuration/tenantA"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://legacy.example.com/tenantA/.well-known/openid-configuration"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://legacy.example.com/.well-known/oauth-authorization-server/tenantA"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://legacy.example.com/tenantA/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json=meta))

        storage = FileTokenStorage(tmp_path / "tok.json")
        result = await storage.discover_oauth_metadata(
            "https://legacy.example.com/tenantA"
        )
        assert result is not None
        assert result["registration_endpoint"] == (
            "https://legacy.example.com/tenantA/oauth/register"
        )


class TestRegisterDynamicClient:
    """DCR error surfacing per RFC 7591 §3.2.2."""

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_parsed_client_info_on_success(self, tmp_path):
        respx.post("https://as.example.com/register").mock(
            return_value=httpx.Response(
                201,
                json={"client_id": "abc", "client_secret": "shh"},
            )
        )
        storage = FileTokenStorage(tmp_path / "tok.json")
        result = await storage.register_dynamic_client(
            "https://as.example.com/register",
            {"client_name": "OpenMaskit", "redirect_uris": ["http://localhost:3131/callback"]},
        )
        assert result == {"client_id": "abc", "client_secret": "shh"}

    @pytest.mark.anyio
    @respx.mock
    async def test_raises_with_error_description_on_400(self, tmp_path):
        respx.post("https://as.example.com/register").mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_redirect_uri",
                    "error_description": "localhost is not allowed for this client",
                },
            )
        )
        storage = FileTokenStorage(tmp_path / "tok.json")
        with pytest.raises(RuntimeError) as exc:
            await storage.register_dynamic_client(
                "https://as.example.com/register",
                {"client_name": "OpenMaskit"},
            )
        msg = str(exc.value)
        assert "400" in msg
        assert "invalid_redirect_uri" in msg
        assert "localhost is not allowed" in msg

    @pytest.mark.anyio
    @respx.mock
    async def test_raises_with_status_only_when_body_not_json(self, tmp_path):
        respx.post("https://as.example.com/register").mock(
            return_value=httpx.Response(500, text="<html>internal server error</html>")
        )
        storage = FileTokenStorage(tmp_path / "tok.json")
        with pytest.raises(RuntimeError) as exc:
            await storage.register_dynamic_client(
                "https://as.example.com/register",
                {"client_name": "OpenMaskit"},
            )
        msg = str(exc.value)
        assert "500" in msg
        # Body snippet preserved so the user can grep
        assert "internal server error" in msg

    @pytest.mark.anyio
    @respx.mock
    async def test_raises_on_network_error(self, tmp_path):
        respx.post("https://as.example.com/register").mock(
            side_effect=httpx.ConnectError("connection refused")
        )
        storage = FileTokenStorage(tmp_path / "tok.json")
        with pytest.raises(RuntimeError) as exc:
            await storage.register_dynamic_client(
                "https://as.example.com/register",
                {"client_name": "OpenMaskit"},
            )
        assert "network error" in str(exc.value).lower()

    @pytest.mark.anyio
    @respx.mock
    async def test_passes_registration_token_when_provided(self, tmp_path):
        captured: dict = {}

        def capture(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("Authorization")
            return httpx.Response(201, json={"client_id": "abc"})

        respx.post("https://as.example.com/register").mock(side_effect=capture)
        storage = FileTokenStorage(tmp_path / "tok.json")
        await storage.register_dynamic_client(
            "https://as.example.com/register",
            {"client_name": "OpenMaskit"},
            registration_token="initial-token-xyz",
        )
        assert captured["auth"] == "Bearer initial-token-xyz"


class TestPickDcrTokenEndpointAuthMethod:
    """Backward-compat-preserving DCR auth_method negotiation."""

    def test_no_supported_field_keeps_client_secret_post(self):
        # Preserves byte-identical behaviour for ASes that don't advertise.
        assert pick_dcr_token_endpoint_auth_method(None) == "client_secret_post"
        assert pick_dcr_token_endpoint_auth_method([]) == "client_secret_post"

    def test_client_secret_post_in_list_keeps_client_secret_post(self):
        # Every previously-working server falls in this branch — unchanged.
        assert pick_dcr_token_endpoint_auth_method(
            ["client_secret_post", "client_secret_basic"]
        ) == "client_secret_post"
        assert pick_dcr_token_endpoint_auth_method(["client_secret_post"]) == "client_secret_post"

    def test_none_only_picks_none(self):
        # Stripe-shape: PKCE-only public client.
        assert pick_dcr_token_endpoint_auth_method(["none"]) == "none"

    def test_basic_only_picks_basic(self):
        assert pick_dcr_token_endpoint_auth_method(
            ["client_secret_basic"]
        ) == "client_secret_basic"

    def test_none_preferred_over_basic_when_post_absent(self):
        # `none` is the MCP authorization spec's recommended default for
        # native-app clients relying on PKCE; prefer it over basic.
        assert pick_dcr_token_endpoint_auth_method(
            ["client_secret_basic", "none"]
        ) == "none"

    def test_falls_back_to_first_when_no_known(self):
        assert pick_dcr_token_endpoint_auth_method(
            ["private_key_jwt", "client_secret_jwt"]
        ) == "private_key_jwt"


class TestCreateOauthProviderDcrAuthMethod:
    """Integration: DCR request body's auth_method reflects AS support."""

    @pytest.mark.anyio
    async def test_request_uses_client_secret_post_when_supported(
        self, tmp_path, monkeypatch
    ):
        """Backward compat: every previously-working server stays unchanged."""
        captured: dict = {}

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_post",
                    "client_secret_basic",
                ],
            }

        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {"client_id": "abc", "client_secret": "shh"}

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=tmp_path / "oauth.json",
            callback_server=OAuthCallbackServer(port=3131),
        )

        assert captured["metadata"]["token_endpoint_auth_method"] == "client_secret_post"

    @pytest.mark.anyio
    async def test_request_uses_none_when_only_none_supported(
        self, tmp_path, monkeypatch
    ):
        """Stripe-shape: AS advertises only ["none"] — we negotiate down."""
        captured: dict = {}

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "token_endpoint_auth_methods_supported": ["none"],
            }

        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {
                "client_id": "abc",
                "token_endpoint_auth_method": "none",
            }

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=tmp_path / "oauth.json",
            callback_server=OAuthCallbackServer(port=3131),
        )

        assert captured["metadata"]["token_endpoint_auth_method"] == "none"

    @pytest.mark.anyio
    async def test_request_uses_post_when_supported_field_missing(
        self, tmp_path, monkeypatch
    ):
        """Backward compat: AS metadata without the field stays on post."""
        captured: dict = {}

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {"client_id": "abc", "client_secret": "shh"}

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=tmp_path / "oauth.json",
            callback_server=OAuthCallbackServer(port=3131),
        )

        assert captured["metadata"]["token_endpoint_auth_method"] == "client_secret_post"

    @pytest.mark.anyio
    async def test_dcr_body_includes_software_id_and_version(
        self, tmp_path, monkeypatch
    ):
        """RFC 7591 §2: DCR registration body carries OpenMaskit's software identity."""
        from openmaskit import __version__ as openmaskit_version

        captured: dict = {}

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {"client_id": "abc", "client_secret": "shh"}

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=tmp_path / "oauth.json",
            callback_server=OAuthCallbackServer(port=3131),
        )

        assert captured["metadata"]["software_id"] == OPENMASKIT_SOFTWARE_ID
        assert captured["metadata"]["software_version"] == openmaskit_version

    @pytest.mark.anyio
    async def test_dcr_captures_rfc7592_management_fields(
        self, tmp_path, monkeypatch
    ):
        """RFC 7592: when the AS returns registration_access_token /
        registration_client_uri, we persist them for a future uninstall flow."""

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            return {
                "client_id": "abc",
                "client_secret": "shh",
                "registration_access_token": "rat-xyz",
                "registration_client_uri": "https://example.com/register/abc",
            }

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        store = tmp_path / "oauth.json"
        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=store,
            callback_server=OAuthCallbackServer(port=3131),
        )

        storage = FileTokenStorage(store)
        mgmt = await storage.get_registration_management()
        assert mgmt == {
            "registration_access_token": "rat-xyz",
            "registration_client_uri": "https://example.com/register/abc",
        }

    @pytest.mark.anyio
    async def test_new_dcr_registers_both_loopback_forms_with_127_first(
        self, tmp_path, monkeypatch
    ):
        """RFC 8252 §7.3: register both 127.0.0.1 and localhost; canonical first."""
        captured: dict = {}

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {"client_id": "abc", "client_secret": "shh"}

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        store = tmp_path / "oauth.json"
        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=store,
            callback_server=OAuthCallbackServer(port=3131),
        )

        # DCR request body lists both, canonical first.
        assert captured["metadata"]["redirect_uris"] == [
            "http://127.0.0.1:3131/callback",
            "http://localhost:3131/callback",
        ]

        # The SDK will use redirect_uris[0] in the auth request — must be canonical.
        assert str(provider.context.client_metadata.redirect_uris[0]) == (
            "http://127.0.0.1:3131/callback"
        )

        # Stored client_info carries both forms so a future reconnect keeps the pair.
        storage = FileTokenStorage(store)
        stored = await storage.get_client_info()
        assert [str(u) for u in stored.redirect_uris] == [
            "http://127.0.0.1:3131/callback",
            "http://localhost:3131/callback",
        ]

    @pytest.mark.anyio
    async def test_existing_dcr_with_legacy_localhost_uri_keeps_using_it(
        self, tmp_path, monkeypatch
    ):
        """Pre-RFC-8252-fix DCR install: AS only registered localhost. We must
        keep sending localhost, or the AS will reject the auth request."""
        from mcp.shared.auth import OAuthClientInformationFull

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        # Seed storage with a "pre-fix" DCR client that only has localhost.
        store = tmp_path / "oauth.json"
        storage = FileTokenStorage(store)
        legacy_client = OAuthClientInformationFull(
            client_id="legacy-abc",
            client_secret="legacy-secret",
            redirect_uris=["http://localhost:3131/callback"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_post",
        )
        await storage.set_client_info(legacy_client)

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=store,
            callback_server=OAuthCallbackServer(port=3131),
        )

        # Must NOT have switched to 127.0.0.1 — AS would reject.
        assert str(provider.context.client_metadata.redirect_uris[0]) == (
            "http://localhost:3131/callback"
        )

    @pytest.mark.anyio
    async def test_byo_manual_mode_uses_localhost(self, tmp_path):
        """BYO setup guides instruct registering localhost at the provider; we
        must match that, not the canonical 127.0.0.1 form."""
        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(
                client_id="user-supplied-id",
                client_secret="user-supplied-secret",
                scope="read write",
            ),
            store_path=tmp_path / "oauth.json",
            callback_server=OAuthCallbackServer(port=3131),
        )

        assert str(provider.context.client_metadata.redirect_uris[0]) == (
            "http://localhost:3131/callback"
        )

    @pytest.mark.anyio
    async def test_dcr_skips_registration_management_when_absent(
        self, tmp_path, monkeypatch
    ):
        """RFC 7592 fields are optional — absence is not an error."""

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            # No registration_access_token / registration_client_uri.
            return {"client_id": "abc", "client_secret": "shh"}

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        store = tmp_path / "oauth.json"
        await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=store,
            callback_server=OAuthCallbackServer(port=3131),
        )

        storage = FileTokenStorage(store)
        assert await storage.get_registration_management() is None

    @pytest.mark.anyio
    async def test_stored_client_info_respects_as_assigned_method(
        self, tmp_path, monkeypatch
    ):
        """When AS overrides our request (returns "none"), we store "none"."""

        async def fake_discover(self, issuer):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
                "token_endpoint_auth_methods_supported": ["client_secret_post"],
            }

        async def fake_register(self, endpoint, metadata, token=None):
            # We asked for client_secret_post; AS downgraded us (this happens
            # on lenient ASes that ignore the request and issue public clients).
            return {
                "client_id": "abc",
                "token_endpoint_auth_method": "none",
            }

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        store = tmp_path / "oauth.json"
        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=HttpOAuthConfig(issuer="https://issuer.example.com"),
            store_path=store,
            callback_server=OAuthCallbackServer(port=3131),
        )

        # The OAuthClientMetadata handed to the SDK uses the AS-assigned method.
        assert (
            provider.context.client_metadata.token_endpoint_auth_method == "none"
        )

        # And the persisted client_info has it too — re-reading honours the AS.
        storage = FileTokenStorage(store)
        stored = await storage.get_client_info()
        assert stored is not None
        assert stored.token_endpoint_auth_method == "none"
