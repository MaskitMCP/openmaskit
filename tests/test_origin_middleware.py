"""Tests for the Origin allow-list middleware.

Covers three layers:
1. The middleware in isolation against a stub app — every code path.
2. The middleware wired into the real Web UI app (``create_app``) — exercising
   the actual /api/* and /ws/* routes and the static-page exemption.
3. The middleware wired into the real MCP endpoint app (``create_mcp_app``) —
   confirming that cross-origin POSTs are rejected before reaching the relay.
"""

from __future__ import annotations

import anyio
import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket, WebSocketDisconnect

from mcp.shared.message import SessionMessage
from mcp.types import JSONRPCMessage

from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore
from maskit.proxy.core import ProxyState, TargetState
from maskit.proxy.http_downstream import create_mcp_app
from maskit.web.app import create_app
from maskit.web.origin import OriginMiddleware, default_localhost_origins


ALLOWED = "http://127.0.0.1:9473"
ALSO_ALLOWED = "http://localhost:9473"
EVIL = "https://evil.example"


# -----------------------------------------------------------------------------
# Stub app + helpers for testing the middleware in isolation
# -----------------------------------------------------------------------------


async def _ok_handler(request):
    return JSONResponse({"ok": True})


async def _echo_ws(websocket: WebSocket):
    await websocket.accept()
    await websocket.send_text("hello")
    await websocket.close()


def _stub_app(allowed_origins=(ALLOWED, ALSO_ALLOWED), protected=("/api/", "/ws/")):
    """Tiny Starlette app with one /api/ POST, one /ws/ websocket, and one /public route."""
    routes = [
        Route("/api/things", _ok_handler, methods=["GET", "POST"]),
        Route("/public/things", _ok_handler, methods=["GET", "POST"]),
        WebSocketRoute("/ws/echo", _echo_ws),
    ]
    middleware = [
        Middleware(
            OriginMiddleware,
            allowed_origins=allowed_origins,
            protected_path_prefixes=protected,
        ),
    ]
    return Starlette(routes=routes, middleware=middleware)


# -----------------------------------------------------------------------------
# Default localhost origins
# -----------------------------------------------------------------------------


class TestDefaultLocalhostOrigins:
    def test_includes_loopback_and_localhost(self):
        origins = default_localhost_origins(9473)
        assert "http://127.0.0.1:9473" in origins
        assert "http://localhost:9473" in origins

    def test_honors_custom_port(self):
        origins = default_localhost_origins(8080)
        assert all(":8080" in o for o in origins)
        assert all(":9473" not in o for o in origins)


# -----------------------------------------------------------------------------
# Middleware against a stub app: HTTP
# -----------------------------------------------------------------------------


class TestMiddlewareHTTP:
    @pytest.mark.anyio
    async def test_no_origin_allows_post_on_protected_path(self):
        """curl / MCP clients / CLI tools send no Origin — must pass through."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_no_origin_allows_get_on_protected_path(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.get("/api/things")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_allowed_origin_passes(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things", headers={"Origin": ALLOWED})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_second_allowed_origin_passes(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things", headers={"Origin": ALSO_ALLOWED})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_disallowed_origin_post_blocked_with_403(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things", headers={"Origin": EVIL})
        assert resp.status_code == 403
        assert "Origin" in resp.json()["error"]

    @pytest.mark.anyio
    async def test_disallowed_origin_get_also_blocked(self):
        """Read endpoints can return secrets too (e.g. /api/.../mappings) — block GETs."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.get("/api/things", headers={"Origin": EVIL})
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_unprotected_path_ignores_origin(self):
        """Static pages and /health aren't behind the check."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/public/things", headers={"Origin": EVIL})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_origin_check_is_case_insensitive_for_header_name(self):
        """ASGI headers come lowercased — but be explicit about the contract."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things", headers={"ORIGIN": EVIL})
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_origin_value_match_is_case_sensitive(self):
        """Browsers serialize Origin in lowercase; we should not silently accept variants."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/things", headers={"Origin": "HTTP://127.0.0.1:9473"}
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_origin_with_trailing_slash_not_accepted(self):
        """Browsers don't append a trailing slash. Variants should be rejected."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/things", headers={"Origin": ALLOWED + "/"}
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_empty_origin_blocked(self):
        """An empty-string Origin is browser-generated and not in our allow-list."""
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as client:
            resp = await client.post("/api/things", headers={"Origin": ""})
        assert resp.status_code == 403


# -----------------------------------------------------------------------------
# Middleware against a stub app: WebSocket
# -----------------------------------------------------------------------------


class TestMiddlewareWebSocket:
    def test_no_origin_allows_websocket(self):
        with TestClient(_stub_app()) as client:
            with client.websocket_connect("/ws/echo") as ws:
                assert ws.receive_text() == "hello"

    def test_allowed_origin_websocket(self):
        with TestClient(_stub_app()) as client:
            with client.websocket_connect("/ws/echo", headers={"Origin": ALLOWED}) as ws:
                assert ws.receive_text() == "hello"

    def test_disallowed_origin_websocket_rejected(self):
        with TestClient(_stub_app()) as client:
            with pytest.raises(WebSocketDisconnect) as excinfo:
                with client.websocket_connect("/ws/echo", headers={"Origin": EVIL}):
                    pass
            assert excinfo.value.code == 4403

    def test_websocket_under_unprotected_prefix_ignores_origin(self):
        app = _stub_app(protected=("/api/",))  # ws/ no longer protected
        with TestClient(app) as client:
            with client.websocket_connect("/ws/echo", headers={"Origin": EVIL}) as ws:
                assert ws.receive_text() == "hello"


# -----------------------------------------------------------------------------
# Integration with the real Web UI app
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture
async def web_store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def web_state(web_store):
    rules = [MaskingRule(tool_name="*", field_path="host", alias_prefix="host")]
    engine = MaskingEngine(rules, web_store)
    await engine.load_aliases()
    await engine.load_mappers()

    proxy_state = ProxyState()
    proxy_state.store = web_store
    target = TargetState(name="test", engine=engine)
    target.tool_schemas = [{"name": "x", "description": "", "inputSchema": {}}]
    target.initialized = True
    proxy_state.targets["test"] = target
    return proxy_state


class TestWebAppIntegration:
    @pytest.mark.anyio
    async def test_api_targets_passes_without_origin(self, web_state):
        """Existing CLI/test callers don't send Origin — must still work."""
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/targets")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_api_targets_with_dashboard_origin(self, web_state):
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/targets", headers={"Origin": ALLOWED})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_api_targets_cross_origin_blocked(self, web_state):
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/targets", headers={"Origin": EVIL})
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_api_rules_create_cross_origin_blocked(self, web_state):
        """POST that would mutate state — the core threat. Must be 403, not 201."""
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.post(
                "/api/targets/test/rules/create",
                json={"tool_name": "*", "field_path": "evil"},
                headers={"Origin": EVIL},
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_mappings_endpoint_cross_origin_blocked(self, web_state):
        """The endpoint that returns the alias map — must reject cross-origin."""
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get(
                "/api/targets/test/mappings", headers={"Origin": EVIL}
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_static_page_unaffected_by_origin(self, web_state):
        """GET / should serve the dashboard regardless of Origin (it's HTML, not data)."""
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/", headers={"Origin": EVIL})
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_health_unaffected_by_origin(self, web_state):
        app = create_app(web_state)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/health", headers={"Origin": EVIL})
        # /health may legitimately return 200 or 503; we only care that it isn't 403
        assert resp.status_code != 403

    @pytest.mark.anyio
    async def test_oauth_callback_unaffected_by_origin(self, web_state):
        """OAuth providers redirect the browser here as a top-level navigation
        (typically no Origin); the route must not be behind the allow-list.

        We're asserting on the middleware decision, not the route handler's
        success — the handler depends on a backend_client wired up in
        ``__main__.py``. As long as control flows past the middleware and into
        the route (even to a 4xx/5xx from the route itself), the middleware
        did its job. We mark the response with an exception handler to make
        this explicit.
        """
        app = create_app(web_state)
        # Stub the state attrs the route handler reaches for, so the handler
        # can run to completion (whatever response it produces) instead of
        # AttributeError-ing before the middleware's decision can be observed.
        app.state.backend_client = None
        app.state.oauth_states = {}
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as c:
            resp = await c.get(
                "/oauth/callback/some-handle",
                headers={"Origin": EVIL},
                follow_redirects=False,
            )
        # Whatever the route's own behavior is, it must not be 403 from middleware.
        assert resp.status_code != 403

    def test_websocket_traffic_cross_origin_blocked(self, web_state):
        """The unmasked-traffic WS is the highest-value target — must reject cross-origin."""
        app = create_app(web_state)
        with TestClient(app) as client:
            with pytest.raises(WebSocketDisconnect) as excinfo:
                with client.websocket_connect(
                    "/ws/targets/test/traffic", headers={"Origin": EVIL}
                ):
                    pass
            assert excinfo.value.code == 4403

    def test_websocket_traffic_allowed_origin(self, web_state):
        app = create_app(web_state)
        with TestClient(app) as client:
            with client.websocket_connect(
                "/ws/targets/test/traffic", headers={"Origin": ALLOWED}
            ) as ws:
                # First payload is initial-state replay (which may be nothing
                # for a fresh target). The connection establishing without a
                # 4403 close is the assertion we care about.
                ws.close()

    @pytest.mark.anyio
    async def test_custom_allowed_origins_via_env_equivalent(self, web_state):
        """Pass allowed_origins explicitly to mirror the MASKIT_ALLOWED_ORIGINS path."""
        extra = "https://maskit.example.com"
        app = create_app(
            web_state,
            allowed_origins=default_localhost_origins(9473) + [extra],
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            resp = await c.get("/api/targets", headers={"Origin": extra})
        assert resp.status_code == 200


# -----------------------------------------------------------------------------
# Integration with the real MCP endpoint app
# -----------------------------------------------------------------------------


@pytest_asyncio.fixture
async def mcp_store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def mcp_state(mcp_store):
    engine = MaskingEngine([], mcp_store, target_name="test")
    await engine.load_aliases()

    state = ProxyState()
    state.mcp_port = 9474
    ds_read_send, ds_read_recv = anyio.create_memory_object_stream[
        SessionMessage | Exception
    ](32)
    target = TargetState(
        name="test",
        engine=engine,
        ds_read_send=ds_read_send,
        ds_read_recv=ds_read_recv,
    )
    target.initialized = True
    target.init_result = {
        "protocolVersion": "2025-03-26",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "test", "version": "0.1"},
    }
    state.targets["test"] = target
    return state


class TestMcpAppIntegration:
    def test_mcp_no_origin_allowed(self, mcp_state):
        """Real MCP clients (Claude Code etc.) send no Origin — must work."""
        app = create_mcp_app(mcp_state)
        with TestClient(app) as client:
            resp = client.post(
                "/test/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                },
            )
        assert resp.status_code == 200

    def test_mcp_cross_origin_blocked(self, mcp_state):
        app = create_mcp_app(mcp_state)
        with TestClient(app) as client:
            resp = client.post(
                "/test/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                },
                headers={"Origin": EVIL},
            )
        assert resp.status_code == 403

    def test_mcp_dashboard_origin_allowed(self, mcp_state):
        """If the dashboard ever calls :9474 directly (e.g. SSE), allow it."""
        app = create_mcp_app(mcp_state)
        with TestClient(app) as client:
            resp = client.post(
                "/test/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"},
                    },
                },
                headers={"Origin": ALLOWED},
            )
        assert resp.status_code == 200
