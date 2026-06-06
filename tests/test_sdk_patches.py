"""Tests for ``PinnedScopeClientMetadata``.

This subclass replaces the earlier ``oauth/sdk_patches.py`` monkey patch with a
mechanism that lives where it acts: the OAuthClientMetadata instance itself.
The MCP SDK reassigns ``client_metadata.scope`` from PRM ``scopes_supported``
during runtime auth refresh / 401 / 403 ``insufficient_scope`` paths
(``mcp/client/auth/oauth2.py`` :565 and :614); the subclass silently keeps the
operator's pinned scope instead of letting the SDK overwrite it.
"""

from __future__ import annotations

import pytest
from mcp.shared.auth import OAuthClientInformationFull

from openmaskit.models import HttpOAuthConfig
from openmaskit.oauth.handler import (
    FileTokenStorage,
    PinnedScopeClientMetadata,
    create_oauth_provider,
)


def _make(scope: str | None) -> PinnedScopeClientMetadata:
    return PinnedScopeClientMetadata(
        redirect_uris=["http://localhost:9473/oauth/callback/h"],
        scope=scope,
    )


class TestPinnedScopeClientMetadata:
    def test_initial_scope_is_preserved(self):
        cm = _make("read:me offline_access")
        assert cm.scope == "read:me offline_access"

    def test_overwrite_after_pinning_is_ignored(self):
        cm = _make("read:me offline_access")
        cm.scope = "read:all:twg"
        assert cm.scope == "read:me offline_access"

    def test_overwrite_with_none_is_ignored(self):
        cm = _make("read:me")
        cm.scope = None
        assert cm.scope == "read:me"

    def test_overwrite_with_empty_string_is_ignored(self):
        cm = _make("read:me")
        cm.scope = ""
        assert cm.scope == "read:me"

    def test_empty_initial_scope_lets_sdk_assign(self):
        """No pinned scope ⇒ SDK retains its spec-compliant assignment behaviour."""
        cm = _make(None)
        cm.scope = "spec:assigned"
        assert cm.scope == "spec:assigned"

        cm = _make("")
        cm.scope = "spec:assigned"
        assert cm.scope == "spec:assigned"

    def test_other_fields_remain_assignable(self):
        cm = _make("read:me")
        cm.client_name = "Renamed"
        assert cm.client_name == "Renamed"

    def test_pin_holds_across_repeated_overwrites(self):
        """The SDK's 401 and 403 paths both reassign; both must be no-ops."""
        cm = _make("read:me offline_access")
        for value in ("read:all:twg", "another:scope", None, ""):
            cm.scope = value
        assert cm.scope == "read:me offline_access"


async def _seed_client_info(tmp_path):
    """Persist a minimal client_info so the runtime-only ``create_oauth_provider``
    has something to read. Install-time writes client_info during the browser
    flow; runtime can't run without it.
    """
    path = tmp_path / "oauth.json"
    storage = FileTokenStorage(path)
    await storage.set_client_info(
        OAuthClientInformationFull(
            client_id="cid",
            client_secret="secret",
            redirect_uris=["http://localhost:9473/oauth/callback/h"],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            token_endpoint_auth_method="client_secret_post",
        )
    )
    return path


class TestCreateOAuthProviderUsesPinnedSubclass:
    @pytest.mark.anyio
    async def test_byo_provider_pins_user_scope(self, tmp_path):
        path = await _seed_client_info(tmp_path)
        oauth_config = HttpOAuthConfig(
            client_id="cid",
            client_secret="secret",
            scope="read:me offline_access read:jira-work",
        )

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=path,
        )

        cm = provider.context.client_metadata
        assert isinstance(cm, PinnedScopeClientMetadata)
        assert cm.scope == "read:me offline_access read:jira-work"

        # Simulate the SDK's 403 insufficient_scope path: the assignment must
        # be a no-op, leaving the operator's scope intact.
        cm.scope = "read:all:twg"
        assert cm.scope == "read:me offline_access read:jira-work"

    @pytest.mark.anyio
    async def test_dcr_provider_pins_joined_scopes(self, tmp_path):
        path = await _seed_client_info(tmp_path)
        oauth_config = HttpOAuthConfig(
            issuer="https://issuer.example.com",
            scopes=["read:me", "offline_access"],
        )

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=path,
        )

        cm = provider.context.client_metadata
        assert isinstance(cm, PinnedScopeClientMetadata)
        assert cm.scope == "read:me offline_access"

        cm.scope = "spec:overwritten"
        assert cm.scope == "read:me offline_access"

    @pytest.mark.anyio
    async def test_provider_with_no_scope_lets_sdk_assign(self, tmp_path):
        path = await _seed_client_info(tmp_path)
        oauth_config = HttpOAuthConfig(client_id="cid", client_secret="secret")

        provider = await create_oauth_provider(
            server_url="https://example.com/mcp",
            oauth_config=oauth_config,
            store_path=path,
        )

        cm = provider.context.client_metadata
        assert cm.scope in (None, "")
        cm.scope = "spec:assigned"
        assert cm.scope == "spec:assigned"
