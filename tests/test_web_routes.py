"""Tests for web API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import MaskingRule
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
    rules = [MaskingRule(tool_name="*", field_path="host", alias_prefix="host")]
    engine = MaskingEngine(rules, store)
    await engine.load_aliases()
    await engine.load_mappers()

    proxy_state = ProxyState()
    proxy_state.store = store
    target = TargetState(name="test", engine=engine)
    target.tool_schemas = [
        {"name": "get_time", "description": "Gets the time", "inputSchema": {}},
        {"name": "get_host", "description": "Gets a host", "inputSchema": {}},
    ]
    target.hidden_tools = {"get_host"}
    target.initialized = True
    proxy_state.targets["test"] = target
    return proxy_state


@pytest_asyncio.fixture
async def client(state):
    # Use a deterministic CSRF token so the AsyncClient can attach it as a
    # default header. The dashboard JS fetches /api/csrf at runtime; tests
    # bypass that round-trip.
    app = create_app(state, csrf_token="test-csrf-token")
    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={
            "X-CSRF-Token": "test-csrf-token",
            "Origin": "http://127.0.0.1:9473",
        },
    ) as c:
        yield c


class TestTargetsAPI:
    @pytest.mark.anyio
    async def test_list_targets(self, client):
        resp = await client.get("/api/targets")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["targets"]) == 1
        assert data["targets"][0]["name"] == "test"
        assert data["targets"][0]["tool_count"] == 2
        assert data["targets"][0]["initialized"] is True


class TestToolsAPI:
    @pytest.mark.anyio
    async def test_list_tools(self, client):
        resp = await client.get("/api/targets/test/tools")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tools"]) == 2
        assert "hidden_tools" not in data

    @pytest.mark.anyio
    async def test_list_tools_with_hidden(self, client):
        resp = await client.get("/api/targets/test/tools?include_hidden=1")
        assert resp.status_code == 200
        data = resp.json()
        assert "hidden_tools" in data
        assert "get_host" in data["hidden_tools"]

    @pytest.mark.anyio
    async def test_missing_target(self, client):
        resp = await client.get("/api/targets/nonexistent/tools")
        assert resp.status_code == 404


class TestRulesAPI:
    @pytest.mark.anyio
    async def test_list_rules(self, client):
        resp = await client.get("/api/targets/test/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert "rules" in data

    @pytest.mark.anyio
    async def test_create_rule(self, client):
        resp = await client.post(
            "/api/targets/test/rules/create",
            json={"tool_name": "get_time", "field_path": "timezone"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["field_path"] == "timezone"
        assert data["tool_name"] == "get_time"

    @pytest.mark.anyio
    async def test_create_rule_missing_field_path(self, client):
        resp = await client.post(
            "/api/targets/test/rules/create",
            json={"tool_name": "get_time"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_create_rule_too_long_name(self, client):
        resp = await client.post(
            "/api/targets/test/rules/create",
            json={"tool_name": "x" * 300, "field_path": "host"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_delete_rule(self, client):
        resp = await client.post(
            "/api/targets/test/rules/create",
            json={"field_path": "to_delete"},
        )
        rule_id = resp.json()["id"]
        del_resp = await client.delete(f"/api/targets/test/rules/{rule_id}/delete")
        assert del_resp.status_code == 200

    @pytest.mark.anyio
    async def test_delete_nonexistent_rule(self, client):
        resp = await client.delete("/api/targets/test/rules/9999/delete")
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_update_rule(self, client):
        resp = await client.post(
            "/api/targets/test/rules/create",
            json={"field_path": "host", "alias_prefix": "old"},
        )
        rule_id = resp.json()["id"]
        upd_resp = await client.post(
            f"/api/targets/test/rules/{rule_id}/update",
            json={"alias_prefix": "new_prefix"},
        )
        assert upd_resp.status_code == 200

    @pytest.mark.anyio
    async def test_missing_target_rules(self, client):
        resp = await client.get("/api/targets/nope/rules")
        assert resp.status_code == 404


class TestMappersAPI:
    @pytest.mark.anyio
    async def test_create_regex_mapper(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "*",
                "mapper_type": "regex_replace",
                "pattern": r"\d{3}-\d{4}",
                "alias_prefix": "phone",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["mapper_type"] == "regex_replace"

    @pytest.mark.anyio
    async def test_create_json_field_mapper(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "tool_name": "*",
                "mapper_type": "json_field_mask",
                "pattern": "user.email",
                "alias_prefix": "email",
            },
        )
        assert resp.status_code == 201

    @pytest.mark.anyio
    async def test_create_mapper_invalid_regex(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": "[invalid",
                "alias_prefix": "x",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_create_mapper_redos_pattern(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": "(a+)+b",
                "alias_prefix": "x",
            },
        )
        assert resp.status_code == 400
        assert "nested quantifiers" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_mapper_pattern_too_long(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": "a" * 600,
                "alias_prefix": "x",
            },
        )
        assert resp.status_code == 400
        assert "too long" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_mapper_unknown_type(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "unknown",
                "pattern": "test",
                "alias_prefix": "x",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_delete_mapper(self, client):
        resp = await client.post(
            "/api/targets/test/mappers/create",
            json={
                "mapper_type": "regex_replace",
                "pattern": r"\d+",
                "alias_prefix": "num",
            },
        )
        mapper_id = resp.json()["id"]
        del_resp = await client.delete(f"/api/targets/test/mappers/{mapper_id}/delete")
        assert del_resp.status_code == 200

    @pytest.mark.anyio
    async def test_delete_nonexistent_mapper(self, client):
        resp = await client.delete("/api/targets/test/mappers/9999/delete")
        assert resp.status_code == 404


class TestHiddenToolsAPI:
    @pytest.mark.anyio
    async def test_list_hidden_tools(self, client):
        resp = await client.get("/api/targets/test/hidden_tools")
        assert resp.status_code == 200
        data = resp.json()
        assert "get_host" in data["hidden_tools"]

    @pytest.mark.anyio
    async def test_toggle_hide(self, client, state):
        resp = await client.post(
            "/api/targets/test/hidden_tools/toggle",
            json={"tool_name": "get_time", "hidden": True},
        )
        assert resp.status_code == 200
        assert resp.json()["hidden"] is True
        target = state.get_target("test")
        assert "get_time" in target.hidden_tools

    @pytest.mark.anyio
    async def test_toggle_unhide(self, client, state):
        resp = await client.post(
            "/api/targets/test/hidden_tools/toggle",
            json={"tool_name": "get_host", "hidden": False},
        )
        assert resp.status_code == 200
        assert resp.json()["hidden"] is False
        target = state.get_target("test")
        assert "get_host" not in target.hidden_tools

    @pytest.mark.anyio
    async def test_toggle_missing_tool_name(self, client):
        resp = await client.post(
            "/api/targets/test/hidden_tools/toggle",
            json={"hidden": True},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_hidden_tools_missing_target(self, client):
        resp = await client.get("/api/targets/nope/hidden_tools")
        assert resp.status_code == 404


class TestMappingsAPI:
    @pytest.mark.anyio
    async def test_list_mappings(self, client):
        resp = await client.get("/api/targets/test/mappings")
        assert resp.status_code == 200
        data = resp.json()
        assert "mappings" in data
