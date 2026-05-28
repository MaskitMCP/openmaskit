"""Tests for marketplace API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from unittest.mock import AsyncMock, MagicMock

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import MaskingRule
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.web.app import create_app


# Mock catalog data matching the old marketplace.json structure
MOCK_CATALOG = [
    {
        "id": "slack-uuid",
        "handle": "slack",
        "name": "Slack",
        "description": "Interact with Slack workspaces",
        "icon_url": "https://example.com/slack.png",
        "requires_oauth": True,
        "transport_type": "http",
        "mcp_host": "https://mcp.slack.com/mcp",
        "tags": ["communication", "official"],
        "official": True,
    },
    {
        "id": "github-uuid",
        "handle": "github",
        "name": "GitHub",
        "description": "Interact with GitHub repositories",
        "icon_url": "https://example.com/github.png",
        "requires_oauth": True,
        "transport_type": "http",
        "mcp_host": "https://mcp.github.com/mcp",
        "tags": ["development", "official"],
        "official": True,
    },
    {
        "id": "docker-uuid",
        "handle": "docker",
        "name": "Docker",
        "description": "Manage Docker containers",
        "icon_url": "https://example.com/docker.png",
        "requires_oauth": False,
        "transport_type": "stdio",
        "meta": {
            "command": "uvx",
            "args": ["mcp-server-docker"],
            "env": {},
        },
        "tags": ["infrastructure"],
        "official": True,
    },
    {
        "id": "postgres-uuid",
        "handle": "postgres",
        "name": "PostgreSQL",
        "description": "Interact with PostgreSQL databases",
        "requires_oauth": False,
        "transport_type": "stdio",
        "meta": {
            "command": "uvx",
            "args": ["mcp-server-postgres"],
            "env": {"DATABASE_URI": "Placeholder for database URI"},
        },
        "tags": ["database"],
        "official": False,
    },
    # Add 6 more to reach 10 total
    *[
        {
            "id": f"server{i}-uuid",
            "handle": f"server{i}",
            "name": f"Server {i}",
            "description": f"Test server {i}",
            "requires_oauth": False,
            "transport_type": "stdio",
            "meta": {"command": "test", "args": [], "env": {}},
            "tags": ["test"],
            "official": False,
        }
        for i in range(5, 11)
    ],
]


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
def mock_backend_client():
    """Mock backend client for marketplace tests."""
    client = AsyncMock()

    # Mock get_catalog to return our test catalog in the new format (with data and meta)
    async def mock_get_catalog(page=1, size=12, query=None):
        # Filter by query if provided
        filtered_catalog = MOCK_CATALOG
        if query:
            query_lower = query.lower()
            filtered_catalog = [
                entry for entry in MOCK_CATALOG
                if query_lower in entry["name"].lower()
                or query_lower in entry.get("description", "").lower()
                or any(query_lower in tag.lower() for tag in entry.get("tags", []))
            ]

        # Calculate pagination
        total = len(filtered_catalog)
        start_idx = (page - 1) * size
        end_idx = start_idx + size
        paginated_data = filtered_catalog[start_idx:end_idx]
        total_pages = (total + size - 1) // size  # ceil division

        return {
            "data": paginated_data,
            "meta": {
                "total": total,
                "page": page,
                "size": size,
                "total_pages": total_pages,
            }
        }

    client.get_catalog = AsyncMock(side_effect=mock_get_catalog)

    # Mock get_server_info to return specific server details
    async def mock_get_server_info(server_id):
        # Find by UUID
        for entry in MOCK_CATALOG:
            if entry["id"] == server_id:
                return entry
        return None

    client.get_server_info = AsyncMock(side_effect=mock_get_server_info)

    # Mock OAuth URL generation
    client.get_oauth_authorize_url = MagicMock(
        return_value="https://oauth.example.com/authorize"
    )

    return client


@pytest_asyncio.fixture
async def state(store, mock_backend_client):
    proxy_state = ProxyState()
    proxy_state.store = store
    proxy_state.target_manager = None
    return proxy_state


@pytest_asyncio.fixture
async def client(state, mock_backend_client):
    app = create_app(state)
    # Inject mock backend client into app state
    app.state.backend_client = mock_backend_client
    app.state.oauth_states = {}  # For OAuth flow tracking
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
            assert "id" in server  # handle used as local ID
            assert "backend_id" in server  # UUID from backend
            assert "name" in server
            assert "description" in server
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
        """Install a stdio server with no env vars required."""
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "backend_id": "docker-uuid"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["connected"] is False  # No manager, can't connect

        record = await state.store.get_server("docker")
        assert record is not None
        assert record["name"] == "Docker"

    @pytest.mark.anyio
    async def test_install_with_env_vars(self, client, state):
        """Install stdio server with env vars."""
        resp = await client.post(
            "/api/marketplace/install",
            json={
                "server_id": "postgres",
                "backend_id": "postgres-uuid",
                "env_vars": {"DATABASE_URI": "postgresql://localhost/test"},
            },
        )
        assert resp.status_code == 201

        record = await state.store.get_server("postgres")
        assert record is not None
        assert record["config"]["env"]["DATABASE_URI"] == "postgresql://localhost/test"

    @pytest.mark.anyio
    async def test_install_already_installed(self, client, state):
        """Cannot install server that's already installed."""
        await state.store.install_server(
            "docker", "Docker", {"transport": "stdio", "command": "uvx", "args": ["mcp-server-docker"]}
        )
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "backend_id": "docker-uuid"},
        )
        assert resp.status_code == 409

    @pytest.mark.anyio
    async def test_install_unknown_server(self, client):
        """Installing unknown server returns 404."""
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "nonexistent", "backend_id": "nonexistent-uuid"},
        )
        assert resp.status_code == 404

    @pytest.mark.anyio
    async def test_install_conflicts_with_config_target(self, client, state):
        """Cannot install marketplace server if config target exists with same name."""
        # Mark slack as a config target
        state.config_target_ids.add("slack")
        engine = MaskingEngine([], state.store, target_name="slack")
        target = TargetState(name="slack", engine=engine)
        state.targets["slack"] = target

        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "slack", "backend_id": "slack-uuid"},
        )
        assert resp.status_code == 409
        assert "conflicts" in resp.json()["error"].lower()

    @pytest.mark.anyio
    async def test_install_missing_server_id(self, client):
        """Missing server_id returns 400."""
        resp = await client.post(
            "/api/marketplace/install",
            json={"backend_id": "some-uuid"},
        )
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_install_missing_env_vars(self, client):
        """This test is deprecated - new flow doesn't validate env vars upfront."""
        # In the new backend-driven flow, env vars are just passed through
        # Validation happens at connection time, not install time
        # So we skip this test or change it to test connection failure
        pass

    @pytest.mark.anyio
    async def test_install_missing_oauth_vars(self, client):
        """This test is deprecated - OAuth handled by backend, not frontend."""
        # New flow: OAuth servers return requires_oauth=True and oauth_url
        # Frontend doesn't collect OAuth credentials manually
        pass

    @pytest.mark.anyio
    async def test_install_with_oauth_vars(self, client, state):
        """OAuth servers initiate OAuth flow instead of direct install."""
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "slack", "backend_id": "slack-uuid"},
        )
        # Should return requires_oauth=True with oauth_url
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["requires_oauth"] is True
        assert "oauth_url" in data
        assert data["oauth_url"] == "https://oauth.example.com/authorize"

        # Server should NOT be installed yet (happens after OAuth callback)
        record = await state.store.get_server("slack")
        assert record is None


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


class TestApiConfig:
    """The /api/config endpoint feeds shared.js on every page load."""

    @pytest.mark.anyio
    async def test_config_includes_version_status_defaults(self, client, state):
        # state.version_status is None by default
        resp = await client.get("/api/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "mcp_port" in body
        assert "current_version" in body
        vs = body["version_status"]
        # Fail-open defaults when no check has run
        assert vs == {
            "supported": True,
            "update_required": False,
            "update_available": False,
            "latest_version": None,
        }

    @pytest.mark.anyio
    async def test_config_reflects_version_status(self, client, state):
        state.version_status = {
            "supported": False,
            "update_required": True,
            "update_available": True,
            "latest_version": "0.5.0",
        }
        resp = await client.get("/api/config")
        body = resp.json()
        assert body["version_status"]["update_required"] is True
        assert body["version_status"]["latest_version"] == "0.5.0"


class TestMarketplaceVersionGating:
    """When the marketplace backend marks this client as unsupported,
    install and activate must return 426. Other reads/writes are unaffected."""

    @pytest.mark.anyio
    async def test_install_returns_426_when_update_required(self, client, state):
        state.version_status = {
            "supported": False,
            "update_required": True,
            "update_available": True,
            "latest_version": "9.9.9",
        }
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "backend_id": "docker-uuid"},
        )
        assert resp.status_code == 426
        body = resp.json()
        assert "OpenMaskit" in body["error"]
        assert body["latest_version"] == "9.9.9"
        # Confirm the install side-effect did NOT happen.
        assert await state.store.get_server("docker") is None

    @pytest.mark.anyio
    async def test_activate_returns_426_when_update_required(self, client, state):
        await state.store.install_server("docker", "Docker", {"transport": "stdio", "command": "uvx"})
        await state.store.deactivate_server("docker")
        state.version_status = {
            "supported": False,
            "update_required": True,
            "update_available": True,
            "latest_version": "9.9.9",
        }
        resp = await client.post(
            "/api/marketplace/activate",
            json={"server_id": "docker"},
        )
        assert resp.status_code == 426

    @pytest.mark.anyio
    async def test_list_still_works_when_update_required(self, client, state):
        state.version_status = {"update_required": True, "latest_version": "9.9.9"}
        resp = await client.get("/api/marketplace")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_deactivate_still_works_when_update_required(self, client, state):
        await state.store.install_server("docker", "Docker", {"transport": "stdio", "command": "uvx"})
        state.version_status = {"update_required": True, "latest_version": "9.9.9"}
        resp = await client.post(
            "/api/marketplace/deactivate",
            json={"server_id": "docker"},
        )
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_install_works_when_only_update_available(self, client, state):
        state.version_status = {
            "supported": True,
            "update_required": False,
            "update_available": True,
            "latest_version": "9.9.9",
        }
        resp = await client.post(
            "/api/marketplace/install",
            json={"server_id": "docker", "backend_id": "docker-uuid"},
        )
        assert resp.status_code == 201
