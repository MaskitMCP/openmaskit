"""Tests for the CSRF middleware.

Three layers, matching the structure of ``test_origin_middleware.py``:

1. The middleware in isolation against a stub app — every code path.
2. The middleware wired into the real Web UI app (``create_app``) — exercising
   the real /api/* mutating routes and the /api/csrf token endpoint.
3. End-to-end behavior of the ``api_csrf`` route — token shape, gating.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.responses import JSONResponse
from starlette.routing import Route

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import MaskingRule
from openmaskit.masking.store import MaskingStore
from openmaskit.proxy.core import ProxyState, TargetState
from openmaskit.web.app import create_app
from openmaskit.web.csrf import CsrfMiddleware, generate_csrf_token


TOKEN = "test-csrf-token"
ALLOWED = "http://127.0.0.1:9473"


# -----------------------------------------------------------------------------
# Stub app + helpers for testing the middleware in isolation
# -----------------------------------------------------------------------------


async def _ok(request):
    return JSONResponse({"ok": True})


def _stub_app(token=TOKEN, protected=("/api/",)):
    routes = [
        Route("/api/things", _ok, methods=["GET", "POST", "PUT", "DELETE", "PATCH"]),
        Route("/public/things", _ok, methods=["GET", "POST"]),
    ]
    middleware = [
        Middleware(CsrfMiddleware, token=token, protected_path_prefixes=protected),
    ]
    return Starlette(routes=routes, middleware=middleware)


# -----------------------------------------------------------------------------
# generate_csrf_token
# -----------------------------------------------------------------------------


class TestGenerateCsrfToken:
    def test_returns_nonempty_string(self):
        assert isinstance(generate_csrf_token(), str)
        assert generate_csrf_token()

    def test_tokens_are_distinct(self):
        a = generate_csrf_token()
        b = generate_csrf_token()
        assert a != b

    def test_token_is_url_safe(self):
        # token_urlsafe(32) yields ~43 chars from [A-Za-z0-9_-]
        t = generate_csrf_token()
        assert len(t) >= 32
        assert all(c.isalnum() or c in "-_" for c in t)


# -----------------------------------------------------------------------------
# Construction guards
# -----------------------------------------------------------------------------


class TestConstruction:
    def test_empty_token_rejected(self):
        with pytest.raises(ValueError):
            CsrfMiddleware(app=None, token="")


# -----------------------------------------------------------------------------
# Middleware against a stub app
# -----------------------------------------------------------------------------


class TestMiddlewareIsolated:
    @pytest.mark.anyio
    async def test_get_passes_without_token(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.get("/api/things")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_post_without_token_blocked(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post("/api/things")
        assert resp.status_code == 403
        assert resp.json()["error"] == "csrf_invalid"

    @pytest.mark.anyio
    async def test_post_with_wrong_token_blocked(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/things", headers={"X-CSRF-Token": "wrong"}
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_post_with_token_passes(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/things", headers={"X-CSRF-Token": TOKEN}
            )
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_put_without_token_blocked(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.put("/api/things")
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_delete_without_token_blocked(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.delete("/api/things")
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_patch_without_token_blocked(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.patch("/api/things")
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_unprotected_path_ignores_token(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post("/public/things")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_header_lookup_is_case_insensitive(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/things", headers={"x-csrf-token": TOKEN}
            )
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_token_value_match_is_case_sensitive(self):
        async with AsyncClient(
            transport=ASGITransport(app=_stub_app()), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/things", headers={"X-CSRF-Token": TOKEN.upper()}
            )
        assert resp.status_code == 403


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


class TestWebAppCsrf:
    @pytest.mark.anyio
    async def test_csrf_token_route_returns_token(self, web_state):
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/csrf")
        assert resp.status_code == 200
        assert resp.json() == {"token": TOKEN}

    @pytest.mark.anyio
    async def test_csrf_token_route_cross_origin_blocked(self, web_state):
        """Origin middleware sits before CSRF — token endpoint is gated by it."""
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get(
                "/api/csrf", headers={"Origin": "https://evil.example"}
            )
        assert resp.status_code == 403

    @pytest.mark.anyio
    async def test_mutating_post_without_token_blocked(self, web_state):
        """The core threat: a POST that reaches the app without the token is rejected.

        We send an allowed Origin so the request passes the Origin middleware
        and reaches CSRF — otherwise Origin-required-on-mutating would block
        it first and we wouldn't be testing the CSRF code path.
        """
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/targets/test/rules/create",
                json={"tool_name": "*", "field_path": "evil"},
                headers={"Origin": ALLOWED},
            )
        assert resp.status_code == 403
        assert resp.json()["error"] == "csrf_invalid"

    @pytest.mark.anyio
    async def test_mutating_post_with_token_passes(self, web_state):
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.post(
                "/api/targets/test/rules/create",
                json={"tool_name": "*", "field_path": "ok"},
                headers={"X-CSRF-Token": TOKEN, "Origin": ALLOWED},
            )
        # Middleware allows; the route's own response is 201
        assert resp.status_code == 201

    @pytest.mark.anyio
    async def test_get_does_not_need_token(self, web_state):
        """Reads (mappings, traffic, tools, etc.) must not require CSRF."""
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/targets/test/mappings")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_static_page_does_not_need_token(self, web_state):
        app = create_app(web_state, csrf_token=TOKEN)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/")
        assert resp.status_code == 200

    @pytest.mark.anyio
    async def test_auto_generated_token_when_unset(self, web_state):
        """create_app without csrf_token should mint one and expose it on app.state."""
        app = create_app(web_state)
        assert getattr(app.state, "csrf_token", "")
        assert isinstance(app.state.csrf_token, str)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as c:
            resp = await c.get("/api/csrf")
        assert resp.json()["token"] == app.state.csrf_token
