"""Tests for custom target CRUD API routes."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.web.app import create_app
from openmaskit.web.routes.custom_targets import _slugify


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
    proxy_state.config_target_ids = {"from-config"}
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


class TestSlugify:
    def test_basic(self):
        assert _slugify("My Postgres") == "my-postgres"

    def test_special_chars(self):
        assert _slugify("hello@world!") == "hello-world"

    def test_truncate(self):
        long_name = "a" * 100
        assert len(_slugify(long_name)) == 64

    def test_strip_dashes(self):
        assert _slugify("--hello--") == "hello"


class TestCustomTargetCreate:
    @pytest.mark.anyio
    async def test_create_stdio_target(self, client, state):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "My Postgres",
                "transport": "stdio",
                "command": "uvx",
                "args": ["mcp-server-postgres"],
                "env": {"DATABASE_URI": "postgresql://localhost/test"},
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["ok"] is True
        assert data["server_id"] == "my-postgres"

        record = await state.store.get_server("my-postgres")
        assert record is not None
        assert record["name"] == "My Postgres"
        assert record["config"]["transport"] == "stdio"
        assert record["config"]["command"] == "uvx"
        assert record["config"]["args"] == ["mcp-server-postgres"]
        assert record["config"]["env"]["DATABASE_URI"] == "postgresql://localhost/test"

    @pytest.mark.anyio
    async def test_create_http_target(self, client, state):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "My API",
                "transport": "http",
                "url": "https://mcp.example.com/mcp",
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("my-api")
        assert record is not None
        assert record["config"]["transport"] == "http"
        assert record["config"]["url"] == "https://mcp.example.com/mcp"
        assert "oauth" not in record["config"]

    @pytest.mark.anyio
    async def test_create_http_target_with_oauth(self, client, state):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "OAuth Server",
                "transport": "http",
                "url": "https://mcp.example.com/mcp",
                "oauth": {"client_id": "abc", "client_secret": "xyz", "scope": "read"},
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("oauth-server")
        assert record["config"]["oauth"]["client_id"] == "abc"
        assert record["config"]["oauth"]["client_secret"] == "xyz"
        assert record["config"]["oauth"]["scope"] == "read"

    @pytest.mark.anyio
    async def test_create_missing_name(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={"transport": "stdio", "command": "uvx"},
        )
        assert resp.status_code == 400
        assert "name" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_missing_command_for_stdio(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={"name": "test", "transport": "stdio"},
        )
        assert resp.status_code == 400
        assert "command" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_missing_url_for_http(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={"name": "test", "transport": "http"},
        )
        assert resp.status_code == 400
        assert "url" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_conflicts_with_config_target(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={"name": "from-config", "transport": "stdio", "command": "uvx"},
        )
        assert resp.status_code == 409
        assert "config-file" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_duplicate_id(self, client, state):
        await state.store.install_server("my-server", "My Server", {"transport": "stdio", "command": "uvx"})
        resp = await client.post(
            "/api/targets/custom",
            json={"name": "My Server", "transport": "stdio", "command": "npx"},
        )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_create_invalid_transport(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={"name": "test", "transport": "grpc", "command": "foo"},
        )
        assert resp.status_code == 400
        assert "transport" in resp.json()["error"]


class TestCustomTargetContainerNameValidation:
    """When user supplies --name on a `docker run`, validate at submission."""

    @pytest.mark.anyio
    async def test_reserved_openmaskit_prefix_rejected(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "My Container",
                "transport": "stdio",
                "command": "docker",
                "args": ["run", "--rm", "--name", "openmaskit-evil", "img"],
            },
        )
        assert resp.status_code == 400
        assert "reserved" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_invalid_chars_rejected(self, client):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "My Container",
                "transport": "stdio",
                "command": "docker",
                "args": ["run", "--rm", "--name=bad name", "img"],
            },
        )
        assert resp.status_code == 400
        assert "invalid" in resp.json()["error"].lower()

    @pytest.mark.anyio
    async def test_valid_user_name_accepted(self, client, state):
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "My Container",
                "transport": "stdio",
                "command": "docker",
                "args": ["run", "--rm", "--name", "my-pg", "img"],
            },
        )
        assert resp.status_code == 201
        record = await state.store.get_server("my-container")
        assert "--name" in record["config"]["args"]

    @pytest.mark.anyio
    async def test_no_user_name_accepted(self, client):
        # Absent --name → no validation needed, the proxy will inject one.
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "Plain Container",
                "transport": "stdio",
                "command": "docker",
                "args": ["run", "--rm", "img"],
            },
        )
        assert resp.status_code == 201

    @pytest.mark.anyio
    async def test_non_container_command_not_validated(self, client):
        # `uvx --name foo` is not a container, so we don't apply our naming
        # rules to it. (Our `--name` parser would extract "foo" but the
        # is_container_run_command gate prevents that here.)
        resp = await client.post(
            "/api/targets/custom",
            json={
                "name": "uvx thing",
                "transport": "stdio",
                "command": "uvx",
                "args": ["--name", "openmaskit-foo", "some-server"],
            },
        )
        assert resp.status_code == 201


class TestCustomTargetGet:
    @pytest.mark.anyio
    async def test_get_custom_target(self, client, state):
        await state.store.install_server("my-db", "My DB", {"transport": "stdio", "command": "uvx", "args": ["pg"]})
        resp = await client.get("/api/targets/custom/my-db")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "my-db"
        assert data["name"] == "My DB"
        assert data["config"]["command"] == "uvx"

    @pytest.mark.anyio
    async def test_get_config_target_forbidden(self, client):
        resp = await client.get("/api/targets/custom/from-config")
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_get_nonexistent(self, client):
        resp = await client.get("/api/targets/custom/nope")
        assert resp.status_code == 404


class TestCustomTargetUpdate:
    @pytest.mark.anyio
    async def test_update_custom_target(self, client, state):
        await state.store.install_server("my-db", "My DB", {"transport": "stdio", "command": "uvx", "args": []})
        resp = await client.post(
            "/api/targets/custom/my-db/update",
            json={"name": "My DB", "transport": "stdio", "command": "npx", "args": ["new-arg"]},
        )
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        record = await state.store.get_server("my-db")
        assert record["config"]["command"] == "npx"
        assert record["config"]["args"] == ["new-arg"]

    @pytest.mark.anyio
    async def test_update_config_target_forbidden(self, client):
        resp = await client.post(
            "/api/targets/custom/from-config/update",
            json={"name": "x", "transport": "stdio", "command": "y"},
        )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_update_nonexistent(self, client):
        resp = await client.post(
            "/api/targets/custom/nope/update",
            json={"name": "x", "transport": "stdio", "command": "y"},
        )
        assert resp.status_code == 404


class TestCustomTargetDelete:
    @pytest.mark.anyio
    async def test_delete_custom_target(self, client, state):
        await state.store.install_server("my-db", "My DB", {"transport": "stdio", "command": "uvx"})
        resp = await client.post("/api/targets/custom/my-db/delete")
        assert resp.status_code == 200
        assert resp.json()["ok"] is True

        record = await state.store.get_server("my-db")
        assert record is None

    @pytest.mark.anyio
    async def test_delete_config_target_forbidden(self, client):
        resp = await client.post("/api/targets/custom/from-config/delete")
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_delete_nonexistent(self, client):
        resp = await client.post("/api/targets/custom/nope/delete")
        assert resp.status_code == 404


class TestApiTargetsEditable:
    @pytest.mark.anyio
    async def test_config_target_not_editable(self, client, state):
        engine = MaskingEngine([], state.store, target_name="from-config")
        target = TargetState(name="from-config", engine=engine)
        state.targets["from-config"] = target

        resp = await client.get("/api/targets")
        data = resp.json()
        t = next(t for t in data["targets"] if t["name"] == "from-config")
        assert t["editable"] is False

    @pytest.mark.anyio
    async def test_custom_target_editable(self, client, state):
        engine = MaskingEngine([], state.store, target_name="my-custom")
        target = TargetState(name="my-custom", engine=engine)
        state.targets["my-custom"] = target

        resp = await client.get("/api/targets")
        data = resp.json()
        t = next(t for t in data["targets"] if t["name"] == "my-custom")
        assert t["editable"] is True
