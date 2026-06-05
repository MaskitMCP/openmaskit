"""Tests for guardrails API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import ArgumentGuardrail
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


class TestGuardrailsAPI:
    """Test guardrail CRUD operations."""

    @pytest.mark.anyio
    async def test_list_guardrails_empty(self, client):
        """List guardrails returns empty list initially."""
        resp = await client.get("/api/targets/test/guardrails")
        assert resp.status_code == 200
        data = resp.json()
        assert data["guardrails"] == []

    @pytest.mark.anyio
    async def test_create_guardrail_contains(self, client):
        """Create guardrail with contains match type."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "tool_name": "query_db",
                "argument_name": "query",
                "match_type": "contains",
                "pattern": "DROP TABLE",
                "message": "Destructive SQL blocked",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "query_db"
        assert data["argument_name"] == "query"
        assert data["match_type"] == "contains"
        assert data["pattern"] == "DROP TABLE"
        assert data["message"] == "Destructive SQL blocked"
        assert data["active"] is True
        assert "id" in data

    @pytest.mark.anyio
    async def test_create_guardrail_equals(self, client):
        """Create guardrail with equals match type."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "tool_name": "*",
                "argument_name": "force",
                "match_type": "equals",
                "pattern": "true",
                "message": "Force flag not allowed",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["match_type"] == "equals"
        assert data["pattern"] == "true"

    @pytest.mark.anyio
    async def test_create_guardrail_regex(self, client):
        """Create guardrail with regex match type."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "tool_name": "*",
                "argument_name": "path",
                "match_type": "regex",
                "pattern": r"^\.\./",
                "message": "Path traversal blocked",
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["match_type"] == "regex"
        assert data["pattern"] == r"^\.\./"

    @pytest.mark.anyio
    async def test_create_guardrail_defaults(self, client):
        """Create guardrail with default values."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "rm -rf"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["tool_name"] == "*"
        assert data["argument_name"] == "*"
        assert data["match_type"] == "contains"
        assert data["message"] == "Blocked by guardrail"

    @pytest.mark.anyio
    async def test_create_guardrail_missing_pattern(self, client):
        """Create guardrail without pattern fails."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"tool_name": "test"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "pattern is required" in data["error"]

    @pytest.mark.anyio
    async def test_create_guardrail_invalid_match_type(self, client):
        """Create guardrail with invalid match type fails."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "pattern": "test",
                "match_type": "invalid",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "match_type" in data["error"]

    @pytest.mark.anyio
    async def test_create_guardrail_pattern_too_long(self, client):
        """Create guardrail with pattern exceeding max length fails."""
        long_pattern = "x" * 501
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": long_pattern},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "pattern too long" in data["error"]

    @pytest.mark.anyio
    async def test_create_guardrail_message_too_long(self, client):
        """Create guardrail with message exceeding max length fails."""
        long_message = "x" * 501
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "pattern": "test",
                "message": long_message,
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "message too long" in data["error"]

    @pytest.mark.anyio
    async def test_create_guardrail_unsafe_regex(self, client):
        """Create guardrail with unsafe regex pattern fails."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "pattern": "(a+)+b",  # Catastrophic backtracking
                "match_type": "regex",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data

    @pytest.mark.anyio
    async def test_create_guardrail_invalid_regex(self, client):
        """Create guardrail with invalid regex pattern fails."""
        resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={
                "pattern": "[invalid",  # Unclosed bracket
                "match_type": "regex",
            },
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "error" in data

    @pytest.mark.anyio
    async def test_list_guardrails_after_create(self, client):
        """List guardrails shows created guardrails."""
        # Create two guardrails
        await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DELETE FROM"},
        )

        resp = await client.get("/api/targets/test/guardrails")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["guardrails"]) == 2
        patterns = [g["pattern"] for g in data["guardrails"]]
        assert "DROP TABLE" in patterns
        assert "DELETE FROM" in patterns

    @pytest.mark.anyio
    async def test_update_guardrail(self, client):
        """Update existing guardrail."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        guardrail_id = create_resp.json()["id"]

        # Update it
        resp = await client.post(
            f"/api/targets/test/guardrails/{guardrail_id}/update",
            json={
                "pattern": "DROP DATABASE",
                "message": "Updated message",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify update
        list_resp = await client.get("/api/targets/test/guardrails")
        guardrails = list_resp.json()["guardrails"]
        updated = next((g for g in guardrails if g["id"] == guardrail_id), None)
        assert updated is not None
        assert updated["pattern"] == "DROP DATABASE"
        assert updated["message"] == "Updated message"

    @pytest.mark.anyio
    async def test_update_guardrail_toggle_active(self, client):
        """Update guardrail to toggle active flag."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        guardrail_id = create_resp.json()["id"]

        # Deactivate it
        resp = await client.post(
            f"/api/targets/test/guardrails/{guardrail_id}/update",
            json={"active": False},
        )
        assert resp.status_code == 200

        # Verify
        list_resp = await client.get("/api/targets/test/guardrails")
        guardrails = list_resp.json()["guardrails"]
        updated = next((g for g in guardrails if g["id"] == guardrail_id), None)
        assert updated["active"] is False

    @pytest.mark.anyio
    async def test_update_guardrail_invalid_match_type(self, client):
        """Update guardrail with invalid match type fails."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        guardrail_id = create_resp.json()["id"]

        # Try invalid update
        resp = await client.post(
            f"/api/targets/test/guardrails/{guardrail_id}/update",
            json={"match_type": "invalid"},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "match_type" in data["error"]

    @pytest.mark.anyio
    async def test_update_guardrail_unsafe_regex(self, client):
        """Update guardrail pattern to unsafe regex fails."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "safe", "match_type": "regex"},
        )
        guardrail_id = create_resp.json()["id"]

        # Try unsafe regex
        resp = await client.post(
            f"/api/targets/test/guardrails/{guardrail_id}/update",
            json={"pattern": "(a+)+b"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_update_guardrail_no_fields(self, client):
        """Update guardrail with no fields fails."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        guardrail_id = create_resp.json()["id"]

        # Try empty update
        resp = await client.post(
            f"/api/targets/test/guardrails/{guardrail_id}/update",
            json={},
        )
        assert resp.status_code == 400
        data = resp.json()
        assert "No fields to update" in data["error"]

    @pytest.mark.anyio
    async def test_update_guardrail_not_found(self, client):
        """Update non-existent guardrail fails."""
        resp = await client.post("/api/targets/test/guardrails/99999/update",
            json={"pattern": "test"},
        )
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_update_guardrail_invalid_id(self, client):
        """Update guardrail with invalid ID fails."""
        resp = await client.post(
            "/api/targets/test/guardrails/invalid",
            json={"pattern": "test"},
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_delete_guardrail(self, client):
        """Delete existing guardrail."""
        # Create guardrail
        create_resp = await client.post(
            "/api/targets/test/guardrails/create",
            json={"pattern": "DROP TABLE"},
        )
        guardrail_id = create_resp.json()["id"]

        # Delete it
        resp = await client.post(f"/api/targets/test/guardrails/{guardrail_id}/delete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True

        # Verify deletion
        list_resp = await client.get("/api/targets/test/guardrails")
        guardrails = list_resp.json()["guardrails"]
        assert not any(g["id"] == guardrail_id for g in guardrails)

    @pytest.mark.anyio
    async def test_delete_guardrail_not_found(self, client):
        """Delete non-existent guardrail fails."""
        resp = await client.post("/api/targets/test/guardrails/99999/delete")
        assert resp.status_code == 404
        data = resp.json()
        assert "not found" in data["error"].lower()

    @pytest.mark.anyio
    async def test_delete_guardrail_invalid_id(self, client):
        """Delete guardrail with invalid ID fails."""
        resp = await client.post("/api/targets/test/guardrails/invalid/delete")
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_guardrails_target_not_found(self, client):
        """All guardrail endpoints return 404 for missing target."""
        # List
        resp = await client.get("/api/targets/nonexistent/guardrails")
        assert resp.status_code == 404

        # Create
        resp = await client.post(
            "/api/targets/nonexistent/guardrails/create",
            json={"pattern": "test"},
        )
        assert resp.status_code == 404

        # Update
        resp = await client.post("/api/targets/nonexistent/guardrails/1/update",
            json={"pattern": "test"},
        )
        assert resp.status_code == 404

        # Delete
        resp = await client.post("/api/targets/nonexistent/guardrails/1/delete")
        assert resp.status_code == 404
