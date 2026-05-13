"""Tests for marketplace API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import ProxyState, TargetState
from maskit.web.app import create_app


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def state(store):
    proxy_state = ProxyState()
    proxy_state.store = store
    proxy_state.target_manager = None
    return proxy_state


@pytest_asyncio.fixture
async def client(state):
    app = create_app(state)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


class TestMarketplaceList:
    @pytest.mark.anyio
    async def test_list_catalog(self, client):
        resp = await client.get("/api/marketplace")
        assert resp.status_code == 200
        data = resp.json()
        assert "servers" in data
        assert len(data["servers"]) == 10
        names = [s["name"] for s in data["servers"]]
        assert "Slack" in names
        assert "GitHub" in names
        assert "Docker" in names

    @pytest.mark.anyio
    async def test_catalog_entries_have_required_fields(self, client):
        resp = await client.get("/api/marketplace")
        data = resp.json()
        for server in data["servers"]:
            assert "id" in server
            assert "name" in server
            assert "description" in server
            assert "official" in server
            assert "tags" in server
            assert "installed" in server
            assert "active" in server

    @pytest.mark.anyio
    async def test_shows_installed_status(self, client, state):
        store = state.store
        await store.install_server("slack", "Slack", {"transport": "http", "url": "https://mcp.slack.com/mcp"})

        resp = await client.get("/api/marketplace")
        data = resp.json()
        slack = next(s for s in data["servers"] if s["id"] == "slack")
        assert slack["installed"] is True


class TestMarketplaceInstall:
    @pytest.mark.anyio
    async def test_install_server_no_env_vars(self, client, state):
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "env_vars": {}},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True

        record = await state.store.get_server("docker")
        assert record is not None
        assert record["name"] == "Docker"

    @pytest.mark.anyio
    async def test_install_missing_env_vars(self, client):
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "postgres", "env_vars": {}},
        )
        assert resp.status_code == 400
        assert "DATABASE_URI" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_install_with_env_vars(self, client, state):
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "postgres", "env_vars": {"DATABASE_URI": "postgresql://localhost/test"}},
        )
        assert resp.status_code == 201

        record = await state.store.get_server("postgres")
        assert record is not None
        assert record["config"]["env"]["DATABASE_URI"] == "postgresql://localhost/test"

    @pytest.mark.anyio
    async def test_install_already_installed(self, client, state):
        await state.store.install_server("docker", "Docker", {"transport": "stdio", "command": "uvx", "args": ["mcp-server-docker"]})
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "env_vars": {}},
        )
        assert resp.status_code == 409

    @pytest.mark.anyio
    async def test_install_unknown_server(self, client):
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "nonexistent", "env_vars": {}},
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_install_conflicts_with_config_target(self, client, state):
        engine = MaskingEngine([], state.store, target_name="slack")
        target = TargetState(name="slack", engine=engine)
        state.targets["slack"] = target

        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "slack", "env_vars": {}},
        )
        assert resp.status_code == 409
        assert "conflicts" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_install_missing_server_id(self, client):
        resp = await client.post(
            "/api/marketplace/install",
            json={"env_vars": {}},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_install_missing_oauth_vars(self, client):
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "slack", "env_vars": {}, "oauth_vars": {}},
        )
        assert resp.status_code == 400
        assert "client_id" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_install_with_oauth_vars(self, client, state):
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "slack",
                "env_vars": {},
                "oauth_vars": {"client_id": "test_id", "client_secret": "test_secret"},
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("slack")
        assert record is not None
        assert record["config"]["oauth"]["client_id"] == "test_id"
        assert record["config"]["oauth"]["client_secret"] == "test_secret"


class TestMarketplaceDeactivate:
    @pytest.mark.anyio
    async def test_deactivate_installed_server(self, client, state):
        await state.store.install_server("docker", "Docker", {"transport": "stdio", "command": "uvx"})
        resp = await client.post(
            "/api/marketplace/deactivate",
            json={"server_id": "docker"},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        record = await state.store.get_server("docker")
        assert record["active"] is False

    @pytest.mark.anyio
    async def test_deactivate_not_installed(self, client):
        resp = await client.post(
            "/api/marketplace/deactivate",
            json={"server_id": "nonexistent"},
        )
        assert resp.status_code == 404


class TestMarketplaceActivate:
    @pytest.mark.anyio
    async def test_activate_not_installed(self, client):
        resp = await client.post(
            "/api/marketplace/activate",
            json={"server_id": "nonexistent"},
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_activate_already_active_target(self, client, state):
        await state.store.install_server("docker", "Docker", {"transport": "stdio", "command": "uvx"})
        engine = MaskingEngine([], state.store, target_name="docker")
        target = TargetState(name="docker", engine=engine)
        state.targets["docker"] = target

        resp = await client.post(
            "/api/marketplace/activate",
            json={"server_id": "docker"},
        )
        assert resp.status_code == 409
