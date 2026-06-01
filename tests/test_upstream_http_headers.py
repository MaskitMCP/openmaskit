"""Tests for static-header wiring in the HTTP branch of connect_upstream.

connect_upstream has three HTTP sub-branches (backend-Bearer, OAuth provider,
plain). Each must merge any configured static headers into the httpx.AsyncClient
it builds. We exercise this by monkeypatching httpx.AsyncClient + the upstream
transport context-manager to capture the kwargs without opening real sockets.

Also covers the Pydantic-level validator that rejects an `Authorization` entry
in `headers` when `oauth` is configured.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager

import pytest
from pydantic import ValidationError

from openmaskit.models import HttpOAuthConfig, UpstreamHttpConfig
from openmaskit.proxy import upstream as upstream_mod


class _CapturingAsyncClient:
    """Stand-in for httpx.AsyncClient that records constructor kwargs.

    The real client opens a connection pool; that's pointless here and slow.
    """

    last_kwargs: dict | None = None

    def __init__(self, **kwargs):
        type(self).last_kwargs = kwargs
        self.kwargs = kwargs

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False


@asynccontextmanager
async def _noop_streamable(url, http_client=None, **_):
    yield (object(), object(), lambda: None)


@pytest.fixture
def patched_transport(monkeypatch):
    """Replace httpx.AsyncClient + streamable_http_client inside upstream.py
    so the HTTP branches run without doing network I/O.
    """
    _CapturingAsyncClient.last_kwargs = None
    monkeypatch.setattr(upstream_mod.httpx, "AsyncClient", _CapturingAsyncClient)
    monkeypatch.setattr(upstream_mod, "streamable_http_client", _noop_streamable)
    yield _CapturingAsyncClient


class TestPlainHttpBranchHeaders:
    @pytest.mark.anyio
    async def test_static_headers_passed_to_async_client(
        self, patched_transport, tmp_path
    ):
        cfg = UpstreamHttpConfig(
            url="https://example.com/mcp",
            headers={"DD-API-KEY": "abc", "DD-APPLICATION-KEY": "def"},
        )
        async with upstream_mod.connect_upstream(
            cfg, store_path=str(tmp_path / "store.db")
        ):
            pass

        kwargs = patched_transport.last_kwargs
        assert kwargs is not None
        assert kwargs.get("headers") == {
            "DD-API-KEY": "abc",
            "DD-APPLICATION-KEY": "def",
        }
        # Plain branch doesn't use the OAuth provider
        assert kwargs.get("auth") is None

    @pytest.mark.anyio
    async def test_empty_headers_passes_empty_dict_not_none(
        self, patched_transport, tmp_path
    ):
        cfg = UpstreamHttpConfig(url="https://example.com/mcp")
        async with upstream_mod.connect_upstream(
            cfg, store_path=str(tmp_path / "store.db")
        ):
            pass

        kwargs = patched_transport.last_kwargs
        assert kwargs.get("headers") == {}


class TestBackendBearerBranchHeaders:
    """When a backend-managed access_token is present, the Bearer header is
    layered ON TOP of any static headers — both must reach the AsyncClient.
    """

    @pytest.mark.anyio
    async def test_authorization_set_alongside_static_headers(
        self, patched_transport, tmp_path
    ):
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_path = oauth_dir / "ddog.json"
        # Write a backend-managed token file (no client_info)
        token_path.write_text(
            json.dumps({"tokens": {"access_token": "backend-bearer"}})
        )

        cfg = UpstreamHttpConfig(
            url="https://example.com/mcp",
            oauth=HttpOAuthConfig(),  # presence triggers backend-token lookup
            headers={"X-Trace-Id": "abc"},
        )
        async with upstream_mod.connect_upstream(
            cfg,
            store_path=str(tmp_path / "store.db"),
            server_id="ddog",
        ):
            pass

        kwargs = patched_transport.last_kwargs
        assert kwargs is not None
        headers = kwargs.get("headers", {})
        assert headers.get("Authorization") == "Bearer backend-bearer"
        assert headers.get("X-Trace-Id") == "abc"

    @pytest.mark.anyio
    async def test_static_headers_do_not_override_authorization(
        self, patched_transport, tmp_path
    ):
        """Even if the model validator is bypassed somehow, the Bearer header
        must win at runtime — never trust a stale static Authorization to
        clobber a freshly-loaded backend token.
        """
        oauth_dir = tmp_path / "oauth"
        oauth_dir.mkdir(parents=True)
        token_path = oauth_dir / "ddog.json"
        token_path.write_text(
            json.dumps({"tokens": {"access_token": "fresh-bearer"}})
        )

        # Build via model_construct to bypass the validator on purpose.
        cfg = UpstreamHttpConfig.model_construct(
            transport="http",
            url="https://example.com/mcp",
            oauth=HttpOAuthConfig(),
            headers={"Authorization": "Bearer stale-attacker"},
        )
        async with upstream_mod.connect_upstream(
            cfg,
            store_path=str(tmp_path / "store.db"),
            server_id="ddog",
        ):
            pass

        kwargs = patched_transport.last_kwargs
        assert kwargs.get("headers", {}).get("Authorization") == "Bearer fresh-bearer"


class TestOAuthProviderBranchHeaders:
    """When OAuth is configured but no backend token is on disk, connect_upstream
    falls through to the OAuthClientProvider branch. Static headers must still
    be passed to AsyncClient alongside the OAuth `auth=` provider.
    """

    @pytest.mark.anyio
    async def test_static_headers_passed_with_oauth_provider(
        self, patched_transport, tmp_path, monkeypatch
    ):
        sentinel_provider = object()

        async def fake_create_oauth_provider(*args, **kwargs):
            return sentinel_provider

        # Patch the create_oauth_provider symbol at its import site inside
        # connect_upstream (it's imported lazily inside the function).
        from openmaskit.oauth import handler as handler_mod

        monkeypatch.setattr(
            handler_mod, "create_oauth_provider", fake_create_oauth_provider
        )

        cfg = UpstreamHttpConfig(
            url="https://example.com/mcp",
            oauth=HttpOAuthConfig(client_id="cid", client_secret="sec"),
            headers={"X-Tenant": "acme"},
        )
        async with upstream_mod.connect_upstream(
            cfg,
            store_path=str(tmp_path / "store.db"),
            server_id="acme-mcp",
        ):
            pass

        kwargs = patched_transport.last_kwargs
        assert kwargs is not None
        assert kwargs.get("auth") is sentinel_provider
        assert kwargs.get("headers") == {"X-Tenant": "acme"}


class TestModelValidator:
    def test_rejects_authorization_with_oauth(self):
        with pytest.raises(ValidationError) as exc_info:
            UpstreamHttpConfig(
                url="https://example.com/mcp",
                oauth=HttpOAuthConfig(client_id="cid", client_secret="sec"),
                headers={"Authorization": "Bearer attacker"},
            )
        assert "Authorization" in str(exc_info.value)

    def test_rejects_authorization_with_oauth_case_insensitive(self):
        with pytest.raises(ValidationError):
            UpstreamHttpConfig(
                url="https://example.com/mcp",
                oauth=HttpOAuthConfig(client_id="cid", client_secret="sec"),
                headers={"authorization": "Bearer x"},
            )

    def test_rejects_authorization_with_oauth_whitespace(self):
        with pytest.raises(ValidationError):
            UpstreamHttpConfig(
                url="https://example.com/mcp",
                oauth=HttpOAuthConfig(client_id="cid", client_secret="sec"),
                headers={"  Authorization  ": "Bearer x"},
            )

    def test_allows_authorization_without_oauth(self):
        cfg = UpstreamHttpConfig(
            url="https://example.com/mcp",
            headers={"Authorization": "Bearer static"},
        )
        assert cfg.headers == {"Authorization": "Bearer static"}

    def test_allows_non_authorization_headers_with_oauth(self):
        cfg = UpstreamHttpConfig(
            url="https://example.com/mcp",
            oauth=HttpOAuthConfig(client_id="cid", client_secret="sec"),
            headers={"X-Tenant": "acme"},
        )
        assert cfg.headers == {"X-Tenant": "acme"}

    def test_default_headers_is_empty_dict(self):
        cfg = UpstreamHttpConfig(url="https://example.com/mcp")
        assert cfg.headers == {}
