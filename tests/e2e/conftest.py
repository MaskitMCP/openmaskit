"""E2E fixtures: boot a real OpenMaskit subprocess and drive its UI with Playwright.

The suite is opt-in. Run with ``uv run --group e2e pytest tests/e2e -m e2e``.
Tests are skipped when ``OM_E2E_PG_URI`` is not set so the suite is safe to
run in any environment.
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

# Dedicated ports so the suite doesn't clobber a dashboard the user has open.
E2E_WEB_PORT = 19473
E2E_MCP_PORT = 19474

E2E_BASE_URL = f"http://127.0.0.1:{E2E_WEB_PORT}"

_STARTUP_TIMEOUT_S = 45


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) != 0


@pytest.fixture(scope="session")
def pg_uri() -> str:
    uri = os.environ.get("OM_E2E_PG_URI")
    if not uri:
        pytest.skip("OM_E2E_PG_URI not set; skipping e2e (set it to a Postgres URI to run)")
    return uri


@pytest.fixture(scope="session")
def openmaskit_server(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Spawn an isolated OpenMaskit instance on dedicated ports + tmp store.

    Yields the base URL. Tears the process down on session exit.
    """
    for port in (E2E_WEB_PORT, E2E_MCP_PORT):
        if not _port_is_free(port):
            pytest.fail(
                f"Port {port} is in use; the e2e suite expects {E2E_WEB_PORT}/{E2E_MCP_PORT} "
                "to be free so it doesn't clash with a dashboard you have open."
            )

    tmp: Path = tmp_path_factory.mktemp("openmaskit-e2e")
    store_path = tmp / "store.db"
    traffic_path = tmp / "traffic.db"
    config_yaml = tmp / "openmaskit.yaml"
    config_yaml.write_text(
        f'store_path: "{store_path}"\n'
        f"web_port: {E2E_WEB_PORT}\n"
        f"mcp_port: {E2E_MCP_PORT}\n"
    )

    env = {
        **os.environ,
        "OPENMASKIT_HOST": "127.0.0.1",
        "OPENMASKIT_TRAFFIC_DB_PATH": str(traffic_path),
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
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.4)
    else:
        proc.terminate()
        raise RuntimeError(f"OpenMaskit did not become reachable at {E2E_BASE_URL} within {_STARTUP_TIMEOUT_S}s")

    yield E2E_BASE_URL

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    if os.environ.get("OM_E2E_DUMP_LOGS") and proc.stderr:
        sys.stderr.write("--- openmaskit stderr ---\n")
        sys.stderr.write(proc.stderr.read().decode(errors="replace"))
