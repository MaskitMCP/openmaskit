"""Tests for ``oauth/install_flow.prepare_oauth_install``.

Covers what used to live inside ``oauth/handler.create_oauth_provider`` before
the install/runtime split: discovery short-circuits when an issuer is known,
BYO seeds client_info from user-supplied creds, and DCR registers a fresh
client and surfaces the AS-assigned auth method.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import pytest

from openmaskit import __version__ as openmaskit_version
from openmaskit.oauth import install_flow
from openmaskit.oauth.handler import (
    OPENMASKIT_SOFTWARE_ID,
    FileTokenStorage,
)


AS_METADATA = {
    "issuer": "https://issuer.example.com",
    "authorization_endpoint": "https://issuer.example.com/authorize",
    "token_endpoint": "https://issuer.example.com/token",
    "registration_endpoint": "https://issuer.example.com/register",
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
}


def _parse_url_query(url: str) -> dict:
    return {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}


class TestPrepareOAuthInstallByo:
    @pytest.mark.anyio
    async def test_byo_writes_client_info_and_returns_url(self, tmp_path, monkeypatch):
        async def fake_fetch(issuer):
            return AS_METADATA
        monkeypatch.setattr(
            install_flow.discovery, "fetch_oauth_server_metadata", fake_fetch
        )

        store = tmp_path / "oauth.json"
        prep = await install_flow.prepare_oauth_install(
            resolved_url="https://mcp.example.com/mcp",
            mode="byo",
            store_path=store,
            base_url="http://localhost:9473",
            handle="example",
            scope="read write",
            client_id="cid",
            client_secret="ssh",
            issuer="https://issuer.example.com",
        )

        # The URL is well-formed and points at our :9473 callback.
        q = _parse_url_query(prep.oauth_url)
        assert q["response_type"] == "code"
        assert q["client_id"] == "cid"
        assert q["redirect_uri"] == "http://localhost:9473/oauth/callback/example"
        assert q["scope"] == "read write"
        assert q["code_challenge_method"] == "S256"
        assert q["state"] == prep.state

        # InstallPrep carries everything the callback needs.
        assert prep.token_endpoint == "https://issuer.example.com/token"
        assert prep.client_secret == "ssh"
        assert prep.auth_method == "client_secret_post"

        # client_info was persisted for the runtime SDK to load.
        storage = FileTokenStorage(store)
        ci = await storage.get_client_info()
        assert ci.client_id == "cid"
        assert ci.client_secret == "ssh"


class TestPrepareOAuthInstallDcr:
    @pytest.mark.anyio
    async def test_dcr_registers_client_and_uses_callback_uri(
        self, tmp_path, monkeypatch
    ):
        captured: dict = {}

        async def fake_fetch(issuer):
            return AS_METADATA
        async def fake_register(self, endpoint, metadata, token=None):
            captured["metadata"] = metadata
            return {"client_id": "dcr-abc", "client_secret": "dcr-secret"}

        monkeypatch.setattr(
            install_flow.discovery, "fetch_oauth_server_metadata", fake_fetch
        )
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        prep = await install_flow.prepare_oauth_install(
            resolved_url="https://mcp.example.com/mcp",
            mode="dcr",
            store_path=tmp_path / "oauth.json",
            base_url="http://localhost:9473",
            handle="example",
            scope="read",
            issuer="https://issuer.example.com",
        )

        # We register exactly one redirect URI — the new :9473 callback.
        assert captured["metadata"]["redirect_uris"] == [
            "http://localhost:9473/oauth/callback/example"
        ]
        # RFC 7591 §2 identity bits.
        assert captured["metadata"]["software_id"] == OPENMASKIT_SOFTWARE_ID
        assert captured["metadata"]["software_version"] == openmaskit_version

        assert prep.client_id == "dcr-abc"
        assert prep.client_secret == "dcr-secret"

    @pytest.mark.anyio
    async def test_dcr_respects_as_assigned_auth_method(self, tmp_path, monkeypatch):
        """When the AS overrides our requested method (returns "none"), use it."""
        async def fake_fetch(issuer):
            return AS_METADATA
        async def fake_register(self, endpoint, metadata, token=None):
            return {
                "client_id": "abc",
                "token_endpoint_auth_method": "none",
            }
        monkeypatch.setattr(
            install_flow.discovery, "fetch_oauth_server_metadata", fake_fetch
        )
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        prep = await install_flow.prepare_oauth_install(
            resolved_url="https://mcp.example.com/mcp",
            mode="dcr",
            store_path=tmp_path / "oauth.json",
            base_url="http://localhost:9473",
            handle="example",
            scope="read",
            issuer="https://issuer.example.com",
        )
        assert prep.auth_method == "none"

    @pytest.mark.anyio
    async def test_dcr_reuses_existing_client_info(self, tmp_path, monkeypatch):
        """If client_info is already on disk, skip DCR and reuse it."""
        from mcp.shared.auth import OAuthClientInformationFull

        store = tmp_path / "oauth.json"
        storage = FileTokenStorage(store)
        await storage.set_client_info(
            OAuthClientInformationFull(
                client_id="reused",
                client_secret="reused-secret",
                redirect_uris=["http://localhost:9473/oauth/callback/example"],
                grant_types=["authorization_code", "refresh_token"],
                response_types=["code"],
                token_endpoint_auth_method="client_secret_post",
            )
        )

        async def fake_fetch(issuer):
            return AS_METADATA
        async def fake_register(self, endpoint, metadata, token=None):
            raise AssertionError("DCR should not run when client_info exists")
        monkeypatch.setattr(
            install_flow.discovery, "fetch_oauth_server_metadata", fake_fetch
        )
        monkeypatch.setattr(FileTokenStorage, "register_dynamic_client", fake_register)

        prep = await install_flow.prepare_oauth_install(
            resolved_url="https://mcp.example.com/mcp",
            mode="dcr",
            store_path=store,
            base_url="http://localhost:9473",
            handle="example",
            scope="read",
            issuer="https://issuer.example.com",
        )
        assert prep.client_id == "reused"

    @pytest.mark.anyio
    async def test_dcr_raises_when_as_has_no_registration_endpoint(
        self, tmp_path, monkeypatch
    ):
        async def fake_fetch(issuer):
            meta = dict(AS_METADATA)
            meta.pop("registration_endpoint")
            return meta
        monkeypatch.setattr(
            install_flow.discovery, "fetch_oauth_server_metadata", fake_fetch
        )

        with pytest.raises(RuntimeError, match="does not support DCR"):
            await install_flow.prepare_oauth_install(
                resolved_url="https://mcp.example.com/mcp",
                mode="dcr",
                store_path=tmp_path / "oauth.json",
                base_url="http://localhost:9473",
                handle="example",
                scope="read",
                issuer="https://issuer.example.com",
            )


class TestPrepareOAuthInstallDiscoveryFallback:
    @pytest.mark.anyio
    async def test_no_issuer_runs_full_discover(self, tmp_path, monkeypatch):
        """Without an explicit issuer, prepare_oauth_install runs
        discovery.discover() against the MCP URL."""
        called: dict = {}

        async def fake_discover(url):
            called["url"] = url
            return AS_METADATA
        monkeypatch.setattr(install_flow.discovery, "discover", fake_discover)

        prep = await install_flow.prepare_oauth_install(
            resolved_url="https://mcp.example.com/mcp",
            mode="byo",
            store_path=tmp_path / "oauth.json",
            base_url="http://localhost:9473",
            handle="example",
            scope="",
            client_id="cid",
            client_secret="ssh",
        )
        assert called["url"] == "https://mcp.example.com/mcp"
        assert prep.token_endpoint == AS_METADATA["token_endpoint"]
