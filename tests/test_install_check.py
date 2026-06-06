"""Tests for the pre-install runtime check route."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from openmaskit.proxy.core import ProxyState
from openmaskit.web.app import create_app


@pytest_asyncio.fixture
async def client():
    state = ProxyState()
    state.target_manager = None
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


class TestInstallCheck:
    @pytest.mark.anyio
    async def test_command_present(self, client, monkeypatch):
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.shutil.which",
            lambda cmd: "/usr/local/bin/uvx" if cmd == "uvx" else None,
        )

        resp = await client.post("/api/install/check", json={"command": "uvx"})

        assert resp.status_code == 200
        assert resp.json() == {
            "present": True,
            "resolved_command": "uvx",
            "resolved_path": "/usr/local/bin/uvx",
        }

    @pytest.mark.anyio
    async def test_command_missing_known_returns_install_hint(
        self, client, monkeypatch
    ):
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.shutil.which", lambda cmd: None
        )

        resp = await client.post("/api/install/check", json={"command": "uvx"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["present"] is False
        assert "astral" in body["install_hint"]

    @pytest.mark.anyio
    async def test_command_missing_unknown_returns_null_hint(
        self, client, monkeypatch
    ):
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.shutil.which", lambda cmd: None
        )

        resp = await client.post(
            "/api/install/check", json={"command": "obscure-binary"}
        )

        assert resp.status_code == 200
        assert resp.json() == {"present": False, "install_hint": None}

    @pytest.mark.anyio
    async def test_docker_substituted_with_podman(self, client, monkeypatch):
        # container.py says docker maps to podman; install_check should report
        # podman as the resolved command without us touching docker logic.
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.detect_container_runtime",
            lambda: "podman",
        )
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.shutil.which",
            lambda cmd: "/usr/bin/podman" if cmd == "podman" else None,
        )

        resp = await client.post("/api/install/check", json={"command": "docker"})

        assert resp.status_code == 200
        assert resp.json() == {
            "present": True,
            "resolved_command": "podman",
            "resolved_path": "/usr/bin/podman",
        }

    @pytest.mark.anyio
    async def test_docker_no_runtime_returns_install_hint(self, client, monkeypatch):
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.detect_container_runtime",
            lambda: None,
        )

        resp = await client.post("/api/install/check", json={"command": "docker"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["present"] is False
        assert "docker" in body["install_hint"]

    @pytest.mark.anyio
    async def test_docker_present_directly(self, client, monkeypatch):
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.detect_container_runtime",
            lambda: "docker",
        )
        monkeypatch.setattr(
            "openmaskit.web.routes.install_check.shutil.which",
            lambda cmd: "/usr/local/bin/docker" if cmd == "docker" else None,
        )

        resp = await client.post("/api/install/check", json={"command": "docker"})

        assert resp.status_code == 200
        assert resp.json() == {
            "present": True,
            "resolved_command": "docker",
            "resolved_path": "/usr/local/bin/docker",
        }

    @pytest.mark.anyio
    async def test_empty_command_400(self, client):
        resp = await client.post("/api/install/check", json={"command": ""})
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_missing_command_400(self, client):
        resp = await client.post("/api/install/check", json={})
        assert resp.status_code == 400

    @pytest.mark.anyio
    async def test_invalid_json_400(self, client):
        resp = await client.post(
            "/api/install/check",
            content=b"not json",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 400
