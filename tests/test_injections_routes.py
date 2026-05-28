"""Tests for injections API routes."""

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


class TestInjectionsAPI:
    """Test injection CRUD operations."""

    @pytest.mark.anyio
    async def test_list_injections_empty(self, client):
        """List injections returns empty list initially."""
        resp = await client.get("/api/targets/test/injections")
        assert resp.status_code == 200
        data = resp.json()
        assert data["injections"] == []

    @pytest.mark.anyio
    async def test_create_injection_set_mode(self, client):
        """Create injection with set mode."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "tool_name": "query_db",
                "argument_name": "read_only",
                "value": "true",
                "mode": "set",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "query_db"
        assert data["argument_name"] == "read_only"
        assert data["value"] == "true"
        assert data["mode"] == "set"
        assert data["active"] is True
        assert "id" in data

    @pytest.mark.anyio
    async def test_create_injection_default_mode(self, client):
        """Create injection with default mode."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "tool_name": "*",
                "argument_name": "timeout",
                "value": "30",
                "mode": "default",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["mode"] == "default"
        assert data["value"] == "30"

    @pytest.mark.anyio
    async def test_create_injection_append_mode(self, client):
        """Create injection with append mode."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "tool_name": "run_command",
                "argument_name": "flags",
                "value": '["--safe"]',
                "mode": "append",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["mode"] == "append"
        assert data["value"] == '["--safe"]'

    @pytest.mark.anyio
    async def test_create_injection_defaults(self, client):
        """Create injection with default values."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "*"
        assert data["mode"] == "set"

    @pytest.mark.anyio
    async def test_create_injection_json_object(self, client):
        """Create injection with JSON object value."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "config",
                "value": '{"retry": 3, "timeout": 30}',
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["value"] == '{"retry": 3, "timeout": 30}'

    @pytest.mark.anyio
    async def test_create_injection_json_array(self, client):
        """Create injection with JSON array value."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "tags",
                "value": '["production", "critical"]',
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["value"] == '["production", "critical"]'

    @pytest.mark.anyio
    async def test_create_injection_json_string(self, client):
        """Create injection with JSON string value."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "env",
                "value": '"production"',
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["value"] == '"production"'

    @pytest.mark.anyio
    async def test_create_injection_missing_argument_name(self, client):
        """Create injection without argument_name fails."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={"value": "true"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "argument_name is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_injection_missing_value(self, client):
        """Create injection without value fails."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={"argument_name": "test"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "value is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_injection_invalid_mode(self, client):
        """Create injection with invalid mode fails."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "test",
                "value": "true",
                "mode": "invalid",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "mode" in data["error"]

    @pytest.mark.anyio
    async def test_create_injection_invalid_json(self, client):
        """Create injection with invalid JSON value fails."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "test",
                "value": "not-valid-json",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "valid JSON" in data["error"]

    @pytest.mark.anyio
    async def test_create_injection_unclosed_json(self, client):
        """Create injection with unclosed JSON value fails."""
        resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "test",
                "value": '{"key": "value"',
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "valid JSON" in data["error"]

    @pytest.mark.anyio
    async def test_list_injections_after_create(self, client):
        """List injections shows created injections."""
        # Create two injections
        await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "read_only",
                "value": "true",
            },
        )
        await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "timeout",
                "value": "30",
            },
        )

        resp = await client.get("/api/targets/test/injections")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["injections"]) == 2
        arg_names = [i["argument_name"] for i in data["injections"]]
        assert "read_only" in arg_names
        assert "timeout" in arg_names

    @pytest.mark.anyio
    async def test_update_injection(self, client):
        """Update existing injection."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Update it
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/update",
            json={
                "value": "200",
                "mode": "default",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify update
        list_resp = await client.get("/api/targets/test/injections")
        injections = list_resp.json()["injections"]
        updated = next((i for i in injections if i["id"] == injection_id), None)
        assert updated is not None
        assert updated["value"] == "200"
        assert updated["mode"] == "default"

    @pytest.mark.anyio
    async def test_update_injection_toggle_active(self, client):
        """Update injection to toggle active flag."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Deactivate it
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/update",
            json={"active": False},
        )
        assert resp.status_code == 200

        # Verify
        list_resp = await client.get("/api/targets/test/injections")
        injections = list_resp.json()["injections"]
        updated = next((i for i in injections if i["id"] == injection_id), None)
        assert updated["active"] is False

    @pytest.mark.anyio
    async def test_update_injection_invalid_mode(self, client):
        """Update injection with invalid mode fails."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Try invalid update
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/update",
            json={"mode": "invalid"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "mode" in data["error"]

    @pytest.mark.anyio
    async def test_update_injection_invalid_json(self, client):
        """Update injection value to invalid JSON fails."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Try invalid JSON
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/update",
            json={"value": "not-json"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "valid JSON" in data["error"]

    @pytest.mark.anyio
    async def test_update_injection_no_fields(self, client):
        """Update injection with no fields fails."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Try empty update
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/update",
            json={},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "No fields to update" in data["error"]

    @pytest.mark.anyio
    async def test_update_injection_not_found(self, client):
        """Update non-existent injection fails."""
        resp = await client.post("/api/targets/test/injections/99999/update",
            json={"value": "100"},
        )
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_update_injection_invalid_id(self, client):
        """Update injection with invalid ID fails."""
        resp = await client.post(
            "/api/targets/test/injections/invalid",
            json={"value": "100"},
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_delete_injection(self, client):
        """Delete existing injection."""
        # Create injection
        create_resp = await client.post(
            "/api/targets/test/injections/create",
            json={
                "argument_name": "limit",
                "value": "100",
            },
        )
        injection_id = create_resp.json()["id"]

        # Delete it
        resp = await client.post(f"/api/targets/test/injections/{injection_id}/delete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify deletion
        list_resp = await client.get("/api/targets/test/injections")
        injections = list_resp.json()["injections"]
        assert not any(i["id"] == injection_id for i in injections)

    @pytest.mark.anyio
    async def test_delete_injection_not_found(self, client):
        """Delete non-existent injection fails."""
        resp = await client.post("/api/targets/test/injections/99999/delete")
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_delete_injection_invalid_id(self, client):
        """Delete injection with invalid ID fails."""
        resp = await client.post("/api/targets/test/injections/invalid/delete")
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_injections_target_not_found(self, client):
        """All injection endpoints return 404 for missing target."""
        # List
        resp = await client.get("/api/targets/nonexistent/injections")
        assert resp.status_code == 404

        # Create
        resp = await client.post(
            "/api/targets/nonexistent/injections/create",
            json={"argument_name": "test", "value": "true"},
        )
        assert resp.status_code == 404

        # Update
        resp = await client.post(
            "/api/targets/nonexistent/injections/1/update",
            json={"value": "true"},
        )
        assert resp.status_code == 404

        # Delete
        resp = await client.post("/api/targets/nonexistent/injections/1/delete")
        assert resp.status_code == 404
