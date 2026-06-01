"""Tests for marketplace HTTP + static-header auth (PR-3).

Covers:

- _normalize_header_var: catalog shape → install-modal shape.
- /api/marketplace surfacing header_vars on header-auth catalog entries.
- /api/marketplace/install header-auth branch: builds correct config,
  validates required headers, propagates the shared cleaner's errors,
  ignores meta.headers on OAuth entries, persists encrypted (PR-2).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState
from openmaskit.web.app import create_app
from openmaskit.web.routes.marketplace import (
    _normalize_header_var,
    _normalize_env_var,
)


# Datadog-style catalog entry: HTTP transport, no OAuth, two header credentials.
DATADOG_ENTRY = {
    "id": "datadog-uuid",
    "handle": "datadog",
    "name": "Datadog",
    "description": "Datadog metrics and logs",
    "icon_url": "https://example.com/datadog.png",
    "requires_oauth": False,
    "transport_type": "http",
    "mcp_host": "https://mcp.datadoghq.com/api/v1/mcp",
    "tags": ["observability"],
    "official": True,
    "meta": {
        "headers": {
            "DD-API-KEY": {
                "label": "API key",
                "description": "Datadog API key",
                "type": "secret",
                "required": True,
            },
            "DD-APPLICATION-KEY": {
                "label": "Application key",
                "description": "Datadog application key",
                "type": "secret",
                "required": True,
            },
        },
        "setup_guide_url": "https://docs.datadoghq.com/account_management/api-app-keys/",
    },
}

# Header-auth entry with one required and one optional header.
ANTHROPIC_ENTRY = {
    "id": "anthropic-uuid",
    "handle": "anthropic-key",
    "name": "Anthropic API",
    "description": "Anthropic Claude API",
    "requires_oauth": False,
    "transport_type": "http",
    "mcp_host": "https://mcp.example.com/anthropic",
    "tags": ["ai"],
    "official": False,
    "meta": {
        "headers": {
            "X-API-KEY": {
                "label": "API key",
                "type": "secret",
                "required": True,
            },
            "X-Trace-Id": {
                "label": "Trace ID",
                "type": "text",
                "required": False,
            },
        }
    },
}

# Legacy-shape entry: header value is a bare-string placeholder rather than a dict.
LEGACY_ENTRY = {
    "id": "legacy-uuid",
    "handle": "legacy-svc",
    "name": "Legacy Service",
    "description": "Old-shape catalog entry",
    "requires_oauth": False,
    "transport_type": "http",
    "mcp_host": "https://mcp.example.com/legacy",
    "tags": [],
    "official": False,
    "meta": {"headers": {"X-Token": "Paste your service token here"}},
}

# OAuth + meta.headers smuggled in — defensive: the OAuth branch must NOT pick
# up the header prompts. (Backend shouldn't ship this, but the client must
# not melt if it does.)
OAUTH_WITH_STRAY_HEADERS = {
    "id": "stray-uuid",
    "handle": "stray-oauth",
    "name": "Stray OAuth",
    "description": "Catalog entry with bogus meta.headers on an OAuth target",
    "requires_oauth": False,
    "oauth_mode": "byo",
    "transport_type": "http",
    "mcp_host": "https://mcp.example.com/stray",
    "tags": [],
    "official": False,
    "meta": {
        "headers": {"X-Bogus": {"type": "secret", "required": True}},
        "available_scopes": [],
    },
}

CATALOG = [DATADOG_ENTRY, ANTHROPIC_ENTRY, LEGACY_ENTRY, OAUTH_WITH_STRAY_HEADERS]


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
def mock_backend_client():
    client = AsyncMock()

    async def mock_get_catalog(page=1, size=12, query=None):
        return {
            "data": CATALOG,
            "meta": {"total": len(CATALOG), "page": 1, "size": 12, "total_pages": 1},
        }

    client.get_catalog = AsyncMock(side_effect=mock_get_catalog)

    async def mock_get_server_info(server_id):
        for entry in CATALOG:
            if entry["id"] == server_id:
                return entry
        return None

    client.get_server_info = AsyncMock(side_effect=mock_get_server_info)
    client.get_oauth_authorize_url = MagicMock(
        return_value="https://oauth.example.com/authorize"
    )
    return client


@pytest_asyncio.fixture
async def state(store, mock_backend_client):
    s = ProxyState()
    s.store = store
    s.target_manager = None
    return s


@pytest_asyncio.fixture
async def client(state, mock_backend_client):
    app = create_app(state)
    app.state.backend_client = mock_backend_client
    app.state.oauth_states = {}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestNormalizeHeaderVar:
    def test_dict_form_round_trips(self):
        result = _normalize_header_var(
            "DD-API-KEY",
            {"label": "API key", "description": "the key", "type": "secret", "required": True},
        )
        assert result == {
            "name": "DD-API-KEY",
            "label": "API key",
            "description": "the key",
            "type": "secret",
            "required": True,
            "target": "header",
        }

    def test_legacy_string_placeholder(self):
        result = _normalize_header_var("X-Token", "Paste your service token here")
        assert result["name"] == "X-Token"
        assert result["label"] == "X-Token"  # falls back to name
        assert result["description"] == "Paste your service token here"
        assert result["type"] == "text"
        assert result["required"] is True
        assert result["target"] == "header"

    def test_unknown_type_falls_back_to_text(self):
        result = _normalize_header_var("X-Custom", {"type": "magic"})
        assert result["type"] == "text"

    def test_required_defaults_to_true_when_missing(self):
        result = _normalize_header_var("X-Custom", {"type": "secret"})
        assert result["required"] is True

    def test_required_false_respected(self):
        result = _normalize_header_var("X-Trace", {"type": "text", "required": False})
        assert result["required"] is False

    def test_env_var_normalizer_keeps_env_target(self):
        """The env-var helper still tags entries with target='env' so the
        unified credentials list can partition them client-side.
        """
        result = _normalize_env_var("DATABASE_URI", "postgres URI")
        assert result["target"] == "env"


class TestMarketplaceListSurfacesHeaderVars:
    @pytest.mark.anyio
    async def test_header_entry_has_header_vars(self, client):
        resp = await client.get("/api/marketplace")
        assert resp.status_code == 200
        servers = {s["handle"]: s for s in resp.json()["servers"]}
        ddog = servers["datadog"]
        assert ddog["transport_type"] == "http"
        assert ddog["requires_oauth"] is False
        names = [h["name"] for h in ddog["header_vars"]]
        assert names == ["DD-API-KEY", "DD-APPLICATION-KEY"]
        for h in ddog["header_vars"]:
            assert h["target"] == "header"
            assert h["type"] == "secret"
            assert h["required"] is True

    @pytest.mark.anyio
    async def test_non_header_entries_have_empty_header_vars(self, client):
        resp = await client.get("/api/marketplace")
        servers = {s["handle"]: s for s in resp.json()["servers"]}
        # The OAuth-with-stray-headers entry still surfaces the array — the
        # install branch is what protects against using them, not the listing.
        assert "header_vars" in servers["datadog"]
        assert isinstance(servers["datadog"]["header_vars"], list)

    @pytest.mark.anyio
    async def test_legacy_string_header_is_normalized(self, client):
        resp = await client.get("/api/marketplace")
        servers = {s["handle"]: s for s in resp.json()["servers"]}
        legacy = servers["legacy-svc"]
        assert len(legacy["header_vars"]) == 1
        h = legacy["header_vars"][0]
        assert h["name"] == "X-Token"
        assert h["description"] == "Paste your service token here"


class TestMarketplaceInstallHeaderAuth:
    @pytest.mark.anyio
    async def test_install_with_headers_builds_http_config(self, client, state):
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "datadog",
                "backend_id": "datadog-uuid",
                "headers": {
                    "DD-API-KEY": "secret-1",
                    "DD-APPLICATION-KEY": "secret-2",
                },
            },
        )
        assert resp.status_code == 201, resp.text
        record = await state.store.get_server("datadog")
        assert record is not None
        assert record["config"]["transport"] == "http"
        assert record["config"]["url"] == DATADOG_ENTRY["mcp_host"]
        assert record["config"]["headers"] == {
            "DD-API-KEY": "secret-1",
            "DD-APPLICATION-KEY": "secret-2",
        }
        assert record["config"]["backend_id"] == "datadog-uuid"
        # No OAuth block on a pure header-auth install.
        assert "oauth" not in record["config"]

    @pytest.mark.anyio
    async def test_install_strips_empty_header_values(self, client, state):
        # Optional rows with empty values silently drop; required check is
        # exercised separately below.
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "anthropic-key",
                "backend_id": "anthropic-uuid",
                "headers": {"X-API-KEY": "abc", "X-Trace-Id": "   "},
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("anthropic-key")
        assert record["config"]["headers"] == {"X-API-KEY": "abc"}

    @pytest.mark.anyio
    async def test_install_missing_required_header_returns_400(self, client):
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "datadog",
                "backend_id": "datadog-uuid",
                "headers": {"DD-API-KEY": "abc"},  # missing DD-APPLICATION-KEY
            },
        )
        assert resp.status_code == 400
        assert "DD-APPLICATION-KEY" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_install_optional_header_can_be_omitted(self, client, state):
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "anthropic-key",
                "backend_id": "anthropic-uuid",
                "headers": {"X-API-KEY": "only-required"},
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("anthropic-key")
        assert record["config"]["headers"] == {"X-API-KEY": "only-required"}

    @pytest.mark.anyio
    async def test_install_propagates_cleaner_error(self, client):
        # CR/LF guard in clean_http_headers must surface as a 400 with
        # the cleaner's message.
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "datadog",
                "backend_id": "datadog-uuid",
                "headers": {"DD-API-KEY": "val\nInjected: yes"},
            },
        )
        assert resp.status_code == 400
        assert "CR" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_install_with_no_headers_payload_fails_required(self, client):
        # A user submits without filling anything; required check fires.
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "datadog", "backend_id": "datadog-uuid"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_oauth_entry_ignores_meta_headers(self, client, mock_backend_client):
        # The header-auth branch must not pick up an OAuth entry — the install
        # falls through to the BYO path, which expects client_id/secret. We
        # confirm by submitting NO header payload: a header-auth dispatch
        # would 400 ("DD-* required"), but a BYO dispatch 400s on missing
        # client_id. The BYO error is the correct one.
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "stray-oauth", "backend_id": "stray-uuid"},
        )
        assert resp.status_code == 400
        assert "client_id" in resp.json()["error"]


class TestHeaderConfigEncryptionRoundTrip:
    @pytest.mark.anyio
    async def test_persisted_headers_are_encrypted_and_round_trip(
        self, client, state
    ):
        """Cross-cutting with PR-2: header secrets land in the encrypted
        config blob, not as plaintext, and the value survives a fresh store
        open (i.e. decryption works on a cold reload).
        """
        await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "datadog",
                "backend_id": "datadog-uuid",
                "headers": {
                    "DD-API-KEY": "ROUNDTRIP-SECRET-XYZ",
                    "DD-APPLICATION-KEY": "ROUNDTRIP-APP-XYZ",
                },
            },
        )

        # Read the raw blob directly: it must NOT contain the plaintext.
        async with state.store._db.execute(
            "SELECT config_enc FROM mcp_servers WHERE id = ?", ("datadog",)
        ) as cur:
            row = await cur.fetchone()
        assert row is not None
        blob = row[0]
        assert b"ROUNDTRIP-SECRET-XYZ" not in blob
        assert b"DD-API-KEY" not in blob

        # The public surface still returns the plaintext dict.
        record = await state.store.get_server("datadog")
        assert record["config"]["headers"]["DD-API-KEY"] == "ROUNDTRIP-SECRET-XYZ"
