"""Tests for openmaskit.oauth.sdk_patches.

The patch replaces mcp.client.auth.oauth2.get_client_metadata_scopes so that an
explicit per-client_metadata scope override wins over the SDK's spec-mandated
PRM-derived selection. These tests cover:

- Registration / release semantics on the override registry.
- The patched function's frame-inspection lookup of the caller's
  self.context.client_metadata.
- Fall-through to the original SDK function when no override applies.
- handler.create_oauth_provider correctly threading the user's scope into the
  registry for both BYO and DCR install paths.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from mcp.shared.auth import OAuthClientMetadata, ProtectedResourceMetadata

from openmaskit.models import HttpOAuthConfig
from openmaskit.oauth import sdk_patches
from openmaskit.oauth.handler import OAuthCallbackServer, create_oauth_provider
from openmaskit.oauth.sdk_patches import (
    _overrides,
    register_scope_override,
    release_scope_override,
)


@pytest.fixture(autouse=True)
def _clear_overrides():
    """Each test starts with a clean registry and leaves it clean."""
    _overrides.clear()
    yield
    _overrides.clear()


def _make_metadata(scope: str | None = None) -> OAuthClientMetadata:
    return OAuthClientMetadata(
        redirect_uris=["http://localhost:3131/callback"],
        scope=scope,
    )


def _make_prm(scopes: list[str]) -> ProtectedResourceMetadata:
    """Build a PRM whose scopes_supported the SDK fallback would join."""
    return ProtectedResourceMetadata(
        resource="https://example.com/mcp",
        authorization_servers=["https://example.com/as"],
        scopes_supported=scopes,
    )


class _FakeFlow:
    """Mimic the SDK's call-site shape: self.context.client_metadata."""

    def __init__(self, client_metadata: OAuthClientMetadata):
        self.context = SimpleNamespace(client_metadata=client_metadata)

    def call_sdk_scope_selector(self, www_auth_scope, prm, asm=None):
        # Calling through the patched SDK symbol exercises frame inspection.
        from mcp.client.auth import oauth2 as sdk_oauth2

        return sdk_oauth2.get_client_metadata_scopes(www_auth_scope, prm, asm)


class TestRegisterScopeOverride:
    def test_register_stores_scope(self):
        cm = _make_metadata()
        register_scope_override(cm, "read:thing write:thing")
        assert _overrides[id(cm)] == "read:thing write:thing"

    def test_register_ignores_empty_string(self):
        cm = _make_metadata()
        register_scope_override(cm, "")
        assert id(cm) not in _overrides

    def test_register_ignores_none(self):
        cm = _make_metadata()
        register_scope_override(cm, None)
        assert id(cm) not in _overrides

    def test_register_ignores_whitespace_only(self):
        cm = _make_metadata()
        register_scope_override(cm, "   \t")
        assert id(cm) not in _overrides

    def test_release_removes_entry(self):
        cm = _make_metadata()
        register_scope_override(cm, "read:thing")
        release_scope_override(cm)
        assert id(cm) not in _overrides

    def test_release_is_noop_when_missing(self):
        cm = _make_metadata()
        # Should not raise
        release_scope_override(cm)

    def test_distinct_metadata_instances_get_distinct_overrides(self):
        a = _make_metadata()
        b = _make_metadata()
        register_scope_override(a, "scope-a")
        register_scope_override(b, "scope-b")
        assert _overrides[id(a)] == "scope-a"
        assert _overrides[id(b)] == "scope-b"


class TestPatchedGetScopes:
    def test_returns_registered_override(self):
        cm = _make_metadata()
        register_scope_override(cm, "openmaskit:override")
        flow = _FakeFlow(cm)

        prm = _make_prm(["spec:one", "spec:two"])
        result = flow.call_sdk_scope_selector(None, prm)

        assert result == "openmaskit:override"

    def test_override_wins_over_www_auth_scope(self):
        cm = _make_metadata()
        register_scope_override(cm, "openmaskit:override")
        flow = _FakeFlow(cm)

        # WWW-Authenticate scope would normally win over PRM; override beats it
        result = flow.call_sdk_scope_selector("www:auth", None)
        assert result == "openmaskit:override"

    def test_falls_through_to_www_auth_scope_when_no_override(self):
        cm = _make_metadata()
        flow = _FakeFlow(cm)

        result = flow.call_sdk_scope_selector("www:auth", None)
        assert result == "www:auth"

    def test_falls_through_to_prm_scopes_supported_when_no_override(self):
        cm = _make_metadata()
        flow = _FakeFlow(cm)

        prm = _make_prm(["a:scope", "b:scope"])
        result = flow.call_sdk_scope_selector(None, prm)
        assert result == "a:scope b:scope"

    def test_falls_through_to_none_when_no_override_and_no_sources(self):
        cm = _make_metadata()
        flow = _FakeFlow(cm)

        result = flow.call_sdk_scope_selector(None, None)
        assert result is None

    def test_falls_through_when_caller_lacks_self(self):
        """Module-level callers (no `self` in locals) get spec behaviour."""
        from mcp.client.auth import oauth2 as sdk_oauth2

        # Even if some other metadata had been registered, the lookup keys on
        # the caller's specific client_metadata; no caller-self => no match.
        other_cm = _make_metadata()
        register_scope_override(other_cm, "should-not-leak")

        result = sdk_oauth2.get_client_metadata_scopes("www:auth", None)
        assert result == "www:auth"

    def test_falls_through_when_caller_self_lacks_context(self):
        """A caller whose `self` doesn't expose .context falls through cleanly."""

        class NoContext:
            def call_sdk(self, www_auth):
                from mcp.client.auth import oauth2 as sdk_oauth2

                return sdk_oauth2.get_client_metadata_scopes(www_auth, None)

        result = NoContext().call_sdk("www:auth")
        assert result == "www:auth"

    def test_no_override_for_unrelated_metadata_instance(self):
        """Override for one OAuthClientMetadata doesn't bleed into another flow."""
        cm_a = _make_metadata()
        cm_b = _make_metadata()
        register_scope_override(cm_a, "for-a-only")

        flow_b = _FakeFlow(cm_b)
        result = flow_b.call_sdk_scope_selector("www:b", None)
        assert result == "www:b"


class TestInstall:
    def test_install_is_idempotent(self):
        # install() already ran on module import. Calling it again must not
        # double-wrap or otherwise change behaviour.
        from mcp.client.auth import oauth2 as sdk_oauth2

        before = sdk_oauth2.get_client_metadata_scopes
        sdk_patches.install()
        sdk_patches.install()
        after = sdk_oauth2.get_client_metadata_scopes

        assert before is after
        assert getattr(after, "_openmaskit_patched", False) is True

    def test_patched_symbol_is_marked(self):
        from mcp.client.auth import oauth2 as sdk_oauth2

        assert getattr(sdk_oauth2.get_client_metadata_scopes, "_openmaskit_patched", False) is True


class TestCreateOAuthProviderWiresScopeOverride:
    @pytest.mark.anyio
    async def test_byo_mode_registers_user_scope(self, tmp_path):
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(
            client_id="cid",
            client_secret="secret",
            scope="read:me offline_access read:jira-work",
        )

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        cm = provider.context.client_metadata
        assert _overrides.get(id(cm)) == "read:me offline_access read:jira-work"

    @pytest.mark.anyio
    async def test_byo_mode_with_empty_scope_skips_registration(self, tmp_path):
        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(client_id="cid", client_secret="secret")

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        cm = provider.context.client_metadata
        assert id(cm) not in _overrides

    @pytest.mark.anyio
    async def test_dcr_mode_registers_joined_scopes(self, tmp_path, monkeypatch):
        # DCR path needs discovery to find a registration_endpoint; stub it.
        async def fake_discover(self, issuer, mcp_url=None):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            return {"client_id": "dcr-client", "client_secret": "dcr-secret"}

        from openmaskit.oauth.handler import FileTokenStorage

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(
            issuer="https://issuer.example.com",
            scopes=["read:me", "offline_access"],
        )

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        cm = provider.context.client_metadata
        assert _overrides.get(id(cm)) == "read:me offline_access"

    @pytest.mark.anyio
    async def test_dcr_mode_with_no_scopes_skips_registration(
        self, tmp_path, monkeypatch
    ):
        async def fake_discover(self, issuer, mcp_url=None):
            return {
                "registration_endpoint": "https://example.com/register",
                "authorization_endpoint": "https://example.com/authorize",
                "token_endpoint": "https://example.com/token",
            }

        async def fake_register(self, endpoint, metadata, token=None):
            return {"client_id": "dcr-client", "client_secret": "dcr-secret"}

        from openmaskit.oauth.handler import FileTokenStorage

        monkeypatch.setattr(FileTokenStorage, "discover_oauth_metadata", fake_discover)
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        callback_server = OAuthCallbackServer(port=3131)
        oauth_config = HttpOAuthConfig(issuer="https://issuer.example.com")

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=tmp_path / "oauth.json",
            callback_server=callback_server,
        )

        cm = provider.context.client_metadata
        assert id(cm) not in _overrides
