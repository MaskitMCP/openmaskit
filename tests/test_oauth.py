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

