"""E2E fixtures: boot a real OpenMaskit subprocess and drive its UI with Playwright.

The suite is opt-in. Run with ``uv run --group e2e pytest tests/e2e -m e2e``.
The Postgres-using tests skip unless ``OM_E2E_PG_URI`` is set; stub-based
tests run unconditionally and require no external services.

Each test gets a fresh OpenMaskit subprocess against a tmp store dir — slower
than a session-scoped server (~2-3s startup per test) but eliminates an
entire class of inter-test state-leak bugs without writing per-test cleanup
boilerplate.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from playwright.sync_api import Page

# Dedicated ports so the suite doesn't clobber a dashboard the user has open.
E2E_WEB_PORT = 19473
E2E_MCP_PORT = 19474

E2E_BASE_URL = f"http://127.0.0.1:{E2E_WEB_PORT}"

# Tiny MCP stdio server used by the custom-target tests.
STUB_SERVER_PATH = Path(__file__).parent / "fixtures" / "stub_mcp_server.py"

_STARTUP_TIMEOUT_S = 45
_PORT_TEARDOWN_WAIT_S = 5


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0


def _wait_for_port_free(port: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _port_is_free(port):
            return
        time.sleep(0.1)


def _spawn_openmaskit(store_dir: Path) -> subprocess.Popen:
    config_yaml = store_dir / "openmaskit.yaml"
    config_yaml.write_text(
        f'store_path: "{store_dir / "store.db"}"\n'
        f"web_port: {E2E_WEB_PORT}\n"
        f"mcp_port: {E2E_MCP_PORT}\n"
    )
    env = {
        **os.environ,
        "OPENMASKIT_HOST": "127.0.0.1",
        "OPENMASKIT_TRAFFIC_DB_PATH": str(store_dir / "traffic.db"),
    }
    proc = subprocess.Popen(
        ["uv", "run", "openmaskit", str(config_yaml)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=Path(__file__).resolve().parents[2],
    )
    deadline = time.monotonic() + _STARTUP_TIMEOUT_S
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise RuntimeError(
                f"OpenMaskit exited during startup (rc={proc.returncode}).\n--- stderr ---\n{stderr}"
            )
        try:
            r = httpx.get(f"{E2E_BASE_URL}/health", timeout=1.0)
            if r.status_code == 200:
                return proc
        except httpx.HTTPError:
            pass
        time.sleep(0.4)
    proc.terminate()
    raise RuntimeError(f"OpenMaskit did not become reachable at {E2E_BASE_URL} within {_STARTUP_TIMEOUT_S}s")


def _terminate(proc: subprocess.Popen) -> None:
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    if os.environ.get("OM_E2E_DUMP_LOGS") and proc.stderr:
        sys.stderr.write("--- openmaskit stderr ---\n")
        sys.stderr.write(proc.stderr.read().decode(errors="replace"))


@pytest.fixture
def pg_uri() -> str:
    uri = os.environ.get("OM_E2E_PG_URI")
    if not uri:
        pytest.skip("OM_E2E_PG_URI not set; skipping postgres e2e (set it to a Postgres URI to run)")
    return uri


@pytest.fixture
def openmaskit_server(tmp_path: Path) -> str:
    """Fresh OpenMaskit instance per test on dedicated ports + tmp store."""
    _wait_for_port_free(E2E_WEB_PORT, _PORT_TEARDOWN_WAIT_S)
    _wait_for_port_free(E2E_MCP_PORT, _PORT_TEARDOWN_WAIT_S)
    proc = _spawn_openmaskit(tmp_path)
    yield E2E_BASE_URL
    _terminate(proc)


@pytest.fixture
def dashboard_page(openmaskit_server: str, page: Page) -> Page:
    """Pre-navigate to the dashboard and dismiss the welcome modal."""
    page.set_default_timeout(15_000)
    page.goto(openmaskit_server)
    skip = page.get_by_role("button", name="Skip for now")
    if skip.is_visible():
        skip.click()
    return page


def api_client(server_url: str = E2E_BASE_URL) -> httpx.Client:
    """Return an httpx Client pre-loaded with a CSRF token + Origin header.

    The dashboard API's CSRF middleware rejects mutating requests without an
    ``X-CSRF-Token`` header; the Origin middleware rejects cross-origin
    mutations. Tests that bypass the dashboard JS must replay both.

    The returned client is NOT yet opened — use it with ``with api_client() as c:``.
    """
    token = httpx.get(f"{server_url}/api/csrf", timeout=5.0).json()["token"]
    return httpx.Client(
        base_url=server_url,
        timeout=15.0,
        headers={"X-CSRF-Token": token, "Origin": server_url},
    )


def install_stub_via_api(target_id: str, *, server_url: str = E2E_BASE_URL) -> None:
    """Install the stub MCP server as a custom stdio target via the JSON API.

    Skips the Add Server modal — for tests that want a target to exist but
    aren't testing the modal itself. Waits for the target to come online
    (tools/list completes) before returning.
    """
    payload = {
        "name": target_id,
        "transport": "stdio",
        "command": sys.executable,
        "args": [str(STUB_SERVER_PATH)],
        "env": {},
    }
    with api_client(server_url) as client:
        r = client.post("/api/targets/custom", json=payload)
        r.raise_for_status()

    # Wait for the upstream session to initialize so tool schemas are available.
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        r = httpx.get(f"{server_url}/api/targets/{target_id}/tools", timeout=5.0)
        if r.status_code == 200 and r.json().get("tools"):
            return
        time.sleep(0.2)
    raise RuntimeError(f"Stub target {target_id!r} did not initialize within 15s")
