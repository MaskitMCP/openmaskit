"""Tests for the body-size cap middleware."""

from __future__ import annotations

import os

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from openmaskit.web.body_limit import (
    DEFAULT_MAX_REQUEST_BYTES,
    BodySizeLimitMiddleware,
    get_max_request_bytes,
)


async def _echo_body(request: Request):
    body = await request.body()
    return JSONResponse({"len": len(body)})


def _stub_app(max_bytes: int = 1024):
    routes = [Route("/echo", _echo_body, methods=["POST"])]
    middleware = [Middleware(BodySizeLimitMiddleware, max_bytes=max_bytes)]
    return Starlette(routes=routes, middleware=middleware)


class TestConstruction:
    def test_zero_max_rejected(self):
        with pytest.raises(ValueError):
            BodySizeLimitMiddleware(app=None, max_bytes=0)

    def test_negative_max_rejected(self):
        with pytest.raises(ValueError):
            BodySizeLimitMiddleware(app=None, max_bytes=-1)


class TestBodyAccepted:
    @pytest.mark.anyio
    async def test_small_body_passes_through(self):
        app = _stub_app(max_bytes=100)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post("/echo", content=b"hello")
        assert resp.status_code == 200
        assert resp.json() == {"len": 5}

    @pytest.mark.anyio
    async def test_empty_body_passes(self):
        app = _stub_app(max_bytes=100)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post("/echo", content=b"")
        assert resp.status_code == 200
        assert resp.json() == {"len": 0}

    @pytest.mark.anyio
    async def test_body_exactly_at_limit_passes(self):
        app = _stub_app(max_bytes=10)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post("/echo", content=b"0123456789")
        assert resp.status_code == 200
        assert resp.json() == {"len": 10}


class TestBodyRejected:
    @pytest.mark.anyio
    async def test_content_length_header_over_limit_blocked(self):
        """Reject without reading when Content-Length exceeds the cap."""
        app = _stub_app(max_bytes=10)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post("/echo", content=b"x" * 100)
        assert resp.status_code == 413
        body = resp.json()
        assert body["error"] == "request_too_large"
        assert body["max_bytes"] == 10

    @pytest.mark.anyio
    async def test_one_byte_over_limit_blocked(self):
        app = _stub_app(max_bytes=10)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            resp = await c.post("/echo", content=b"x" * 11)
        assert resp.status_code == 413


class TestActualByteCount:
    """Catch callers whose Content-Length lies about the body size."""

    @pytest.mark.anyio
    async def test_lying_content_length_caught_at_read(self):
        """If a client sends Content-Length=5 but pushes 100 bytes, the
        actual-byte count must still trip."""
        # Simulate via raw ASGI rather than httpx, which would correct the CL.
        app = _stub_app(max_bytes=10)

        sent = []

        async def receive_with_big_body():
            # Return a single chunk way larger than the declared CL.
            return {
                "type": "http.request",
                "body": b"x" * 100,
                "more_body": False,
            }

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/echo",
            "headers": [(b"content-length", b"5")],
        }
        # Body cap is 10; declared CL=5 wouldn't trip the header check, so
        # the actual-byte count is the only thing that catches the 100B body.
        await app(scope, receive_with_big_body, send)
        statuses = [m["status"] for m in sent if m["type"] == "http.response.start"]
        assert statuses == [413]


class TestWebsocketBypass:
    @pytest.mark.anyio
    async def test_non_http_scope_passes_through(self):
        """Websocket and lifespan scopes must not be touched."""
        seen = []

        async def downstream(scope, receive, send):
            seen.append(scope.get("type"))

        mw = BodySizeLimitMiddleware(downstream, max_bytes=10)
        await mw({"type": "lifespan"}, lambda: None, lambda m: None)
        await mw({"type": "websocket"}, lambda: None, lambda m: None)
        assert seen == ["lifespan", "websocket"]


class TestGetMaxRequestBytes:
    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("OPENMASKIT_MAX_REQUEST_BYTES", raising=False)
        assert get_max_request_bytes() == DEFAULT_MAX_REQUEST_BYTES

    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_REQUEST_BYTES", "2048")
        assert get_max_request_bytes() == 2048

    def test_non_numeric_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_REQUEST_BYTES", "lots")
        assert get_max_request_bytes() == DEFAULT_MAX_REQUEST_BYTES

    def test_non_positive_env_falls_back(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_REQUEST_BYTES", "0")
        assert get_max_request_bytes() == DEFAULT_MAX_REQUEST_BYTES
        monkeypatch.setenv("OPENMASKIT_MAX_REQUEST_BYTES", "-100")
        assert get_max_request_bytes() == DEFAULT_MAX_REQUEST_BYTES
