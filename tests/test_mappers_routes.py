"""Tests for mappers API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.web.app import create_app


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def state(store):
    engine = MaskingEngine([], store, target_name="test")
    await engine.load_aliases()
    await engine.load_mappers()
    await engine.load_guardrails()
    await engine.load_injections()

    proxy_state = ProxyState()
    proxy_state.store = store
    target = TargetState(name="test", engine=engine)
    target.initialized = True
    proxy_state.targets["test"] = target
    return proxy_state


@pytest_asyncio.fixture
async def client(state):
    app = create_app(state)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestMappersAPI:
    """Test mapper CRUD operations."""

    @pytest.mark.anyio
    async def test_list_mappers_empty(self, client):
        """List mappers returns empty list initially."""
        resp = await client.get("/api/targets/test/mappers")
        assert resp.status_code == 200
        data = resp.json()
        assert data["mappers"] == []

    @pytest.mark.anyio
    async def test_create_mapper_regex_replace(self, client):
        """Create regex_replace mapper."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "get_config",
                "mapper_type": "regex_replace",
                "pattern": r"\b[A-Z0-9]{32}\b",
                "alias_prefix": "api_key",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "get_config"
        assert data["mapper_type"] == "regex_replace"
        assert data["pattern"] == r"\b[A-Z0-9]{32}\b"
        assert data["alias_prefix"] == "api_key"
        assert data["active"] is True
        assert "id" in data

    @pytest.mark.anyio
    async def test_create_mapper_json_field_mask(self, client):
        """Create json_field_mask mapper."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "*",
                "mapper_type": "json_field_mask",
                "pattern": "response.data.token",
                "alias_prefix": "token",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["mapper_type"] == "json_field_mask"
        assert data["pattern"] == "response.data.token"
        assert data["alias_prefix"] == "token"

    @pytest.mark.anyio
    async def test_create_mapper_with_config(self, client):
        """Create mapper with custom config."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": r"\d{3}-\d{2}-\d{4}",
                "alias_prefix": "ssn",
                "config": {"case_sensitive": True},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["config"] == {"case_sensitive": True}

    @pytest.mark.anyio
    async def test_create_mapper_defaults(self, client):
        """Create mapper with default values."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\b\w+@\w+\.\w+\b",
                "alias_prefix": "email",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "*"
        assert data["mapper_type"] == "regex_replace"

    @pytest.mark.anyio
    async def test_create_mapper_missing_pattern(self, client):
        """Create mapper without pattern fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={"alias_prefix": "test"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "pattern is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_missing_alias_prefix_regex(self, client):
        """Create regex_replace mapper without alias_prefix fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": r"\d+",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "alias_prefix is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_missing_alias_prefix_json(self, client):
        """Create json_field_mask mapper without alias_prefix fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": "data.token",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "alias_prefix is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_invalid_type(self, client):
        """Create mapper with invalid mapper_type fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "unknown_type",
                "pattern": "test",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Unknown mapper_type" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_tool_name_too_long(self, client):
        """Create mapper with tool_name exceeding max length fails."""
        long_name = "x" * 257
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": long_name,
                "pattern": r"\d+",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "tool_name too long" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_alias_prefix_too_long(self, client):
        """Create mapper with alias_prefix exceeding max length fails."""
        long_prefix = "x" * 65
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": long_prefix,
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "alias_prefix too long" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_unsafe_regex(self, client):
        """Create mapper with unsafe regex pattern fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": "(a+)+b",  # Catastrophic backtracking
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data

    @pytest.mark.anyio
    async def test_create_mapper_invalid_regex(self, client):
        """Create mapper with invalid regex pattern fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": "[invalid",  # Unclosed bracket
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Invalid regex" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_invalid_dot_path(self, client):
        """Create json_field_mask mapper with invalid dot path fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": "invalid..path",  # Double dot
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Invalid dot-notation path" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_dot_path_with_special_chars(self, client):
        """Create json_field_mask mapper with special characters in path fails."""
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": "data.$token",  # Special character
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Invalid dot-notation path" in data["error"]

    @pytest.mark.anyio
    async def test_create_mapper_json_pattern_too_long(self, client):
        """Create json_field_mask mapper with pattern exceeding max length fails."""
        long_pattern = ".".join(["field"] * 100)  # Very long dot path
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": long_pattern,
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Pattern too long" in data["error"]

    @pytest.mark.anyio
    async def test_list_mappers_after_create(self, client):
        """List mappers shows created mappers."""
        # Create two mappers
        await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\b[A-Z0-9]{32}\b",
                "alias_prefix": "api_key",
            },
        )
        await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": "data.token",
                "alias_prefix": "token",
            },
        )

        resp = await client.get("/api/targets/test/mappers")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["mappers"]) == 2

    @pytest.mark.anyio
    async def test_list_mappers_filter_by_tool(self, client):
        """List mappers filters by tool_name query param."""
        # Create mappers for different tools
        await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "get_config",
                "pattern": r"\d+",
                "alias_prefix": "config",
            },
        )
        await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "get_secrets",
                "pattern": r"\w+",
                "alias_prefix": "secret",
            },
        )

        # Filter by tool_name
        resp = await client.get("/api/targets/test/mappers?tool_name=get_config")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["mappers"]) == 1
        assert data["mappers"][0]["tool_name"] == "get_config"

    @pytest.mark.anyio
    async def test_update_mapper(self, client):
        """Update existing mapper."""
        # Create mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": "number",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Update it
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/update",
            json={
                "pattern": r"\d{4}",
                "alias_prefix": "year",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify update
        list_resp = await client.get("/api/targets/test/mappers")
        mappers = list_resp.json()["mappers"]
        updated = next((m for m in mappers if m["id"] == mapper_id), None)
        assert updated is not None
        assert updated["pattern"] == r"\d{4}"
        assert updated["alias_prefix"] == "year"

    @pytest.mark.anyio
    async def test_update_mapper_missing_pattern(self, client):
        """Update mapper without pattern fails."""
        # Create mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": "number",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Try update without pattern
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/update",
            json={"alias_prefix": "test"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "pattern is required" in data["error"]

    @pytest.mark.anyio
    async def test_update_mapper_missing_alias_prefix(self, client):
        """Update mapper without alias_prefix fails."""
        # Create mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": "number",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Try update without alias_prefix
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/update",
            json={"pattern": r"\d{4}"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "alias_prefix is required" in data["error"]

    @pytest.mark.anyio
    async def test_update_mapper_unsafe_regex(self, client):
        """Update mapper with unsafe regex pattern fails."""
        # Create mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": "number",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Try unsafe regex
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/update",
            json={
                "pattern": "(a+)+b",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_update_mapper_invalid_dot_path(self, client):
        """Update json_field_mask mapper with invalid dot path fails."""
        # Create json_field_mask mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "json_field_mask",
                "pattern": "data.token",
                "alias_prefix": "token",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Try invalid dot path
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/update",
            json={
                "pattern": "invalid..path",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "Invalid dot-notation path" in data["error"]

    @pytest.mark.anyio
    async def test_update_mapper_not_found(self, client):
        """Update non-existent mapper fails."""
        resp = await client.post("/api/targets/test/mappers/99999/update",
            json={
                "pattern": r"\d+",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_update_mapper_invalid_id(self, client):
        """Update mapper with invalid ID fails."""
        resp = await client.post(
            "/api/targets/test/mappers/invalid",
            json={
                "pattern": r"\d+",
                "alias_prefix": "test",
            },
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_delete_mapper(self, client):
        """Delete existing mapper."""
        # Create mapper
        create_resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "pattern": r"\d+",
                "alias_prefix": "number",
            },
        )
        mapper_id = create_resp.json()["id"]

        # Delete it
        resp = await client.post(f"/api/targets/test/mappers/{mapper_id}/delete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify deletion
        list_resp = await client.get("/api/targets/test/mappers")
        mappers = list_resp.json()["mappers"]
        assert not any(m["id"] == mapper_id for m in mappers)

    @pytest.mark.anyio
    async def test_delete_mapper_not_found(self, client):
        """Delete non-existent mapper fails."""
        resp = await client.post("/api/targets/test/mappers/99999/delete")
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_delete_mapper_invalid_id(self, client):
        """Delete mapper with invalid ID fails."""
        resp = await client.post("/api/targets/test/mappers/invalid/delete")
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_mappers_target_not_found(self, client):
        """All mapper endpoints return 404 for missing target."""
        # List
        resp = await client.get("/api/targets/nonexistent/mappers")
        assert resp.status_code == 404

        # Create
        resp = await client.post(
            "/api/targets/nonexistent/mappers/create",
            json={"pattern": r"\d+", "alias_prefix": "test"},
        )
        assert resp.status_code == 404

        # Update
        resp = await client.post(
            "/api/targets/nonexistent/mappers/1/update",
            json={"pattern": r"\d+", "alias_prefix": "test"},
        )
        assert resp.status_code == 404

        # Delete
        resp = await client.post("/api/targets/nonexistent/mappers/1/delete")
        assert resp.status_code == 404


class TestMappersPreviewWithResult:
    """The preview endpoint must mirror the live engine's scope: text blocks
    and structuredContent string leaves. Patterns that only match the
    pretty-printed JSON wrapper (e.g. `"id": ([0-9]+)`) should NOT report
    matches, even though they would have matched the old `text`-style preview
    that scanned the JSON.stringify'd response. This is the bug class the
    Tackt-style catalog hit."""

    @pytest.mark.anyio
    async def test_regex_on_string_value_in_structured_content_matches(self, client):
        """A regex that targets a string leaf inside structuredContent should
        match — same surface live will scan."""
        resp = await client.post(
            "/api/targets/test/mappers/preview",
            json={
                "pattern": r"[\w.+-]+@[\w.-]+",
                "alias_prefix": "email",
                "result": {
                    "structuredContent": {
                        "items": [
                            {"name": "Alice", "value": "hi, my email is alice@example.com"},
                            {"name": "Bob", "value": "no email here"},
                        ]
                    }
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        originals = [m["original"] for m in data["matches"]]
        assert originals == ["alice@example.com"]

    @pytest.mark.anyio
    async def test_regex_targeting_json_key_value_pair_shows_zero(self, client):
        """The exact case from the Tackt bug report: pattern `"id": ([0-9]+)`
        against a response where `id` is an int field in structuredContent.
        Preview MUST show zero matches because live will mask zero — there is
        no string leaf containing the literal characters `"id": `."""
        resp = await client.post(
            "/api/targets/test/mappers/preview",
            json={
                "pattern": r'"id": ([0-9]+)',
                "alias_prefix": "cat_id",
                "result": {
                    "content": [
                        {"type": "text", "text": "Categories: Dressuurpaard (id:1), Springpaard (id:2)"}
                    ],
                    "structuredContent": {
                        "categories": [
                            {"id": 1, "name": "Dressuurpaard"},
                            {"id": 2, "name": "Springpaard"},
                        ]
                    },
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["matches"] == []

    @pytest.mark.anyio
    async def test_regex_on_text_block_matches(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/preview",
            json={
                "pattern": r"\bsk-[a-z0-9]+\b",
                "alias_prefix": "api_key",
                "result": {
                    "content": [
                        {"type": "text", "text": "Using token sk-abc123 for the call."}
                    ]
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        originals = [m["original"] for m in data["matches"]]
        assert originals == ["sk-abc123"]

    @pytest.mark.anyio
    async def test_dedups_same_value_across_surfaces(self, client):
        """A single real value appearing in both a text block and structuredContent
        should produce ONE alias, not two."""
        resp = await client.post(
            "/api/targets/test/mappers/preview",
            json={
                "pattern": r"\bsecret_\d+\b",
                "alias_prefix": "leak",
                "result": {
                    "content": [{"type": "text", "text": "Found secret_42 in log."}],
                    "structuredContent": {"hit": "secret_42"},
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        aliases = {m["alias"] for m in data["matches"]}
        assert aliases == {"leak_1"}

    @pytest.mark.anyio
    async def test_legacy_text_path_still_works(self, client):
        """External callers that POST `text` (not `result`) keep working."""
        resp = await client.post(
            "/api/targets/test/mappers/preview",
            json={
                "pattern": r"\d+",
                "alias_prefix": "n",
                "text": "abc 123 def 456",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        originals = [m["original"] for m in data["matches"]]
        assert originals == ["123", "456"]
