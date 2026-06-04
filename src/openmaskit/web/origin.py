"""Origin allow-list middleware for browser-attack defense.

OpenMaskit's dashboard (:9473) and MCP endpoint (:9474) bind to localhost on the
user's own machine. That doesn't mean they're safe from attack: any webpage the
user visits in their browser can issue cross-origin ``fetch()`` and WebSocket
handshakes against ``http://127.0.0.1:9473`` / ``:9474``. Without an Origin
check, a malicious page could dump every secret OpenMaskit has ever masked or
subscribe to the live unmasked-traffic stream.

This middleware enforces:

* If the request carries an ``Origin`` header, it MUST be in the allow-list.
  Browsers always attach ``Origin`` to cross-origin ``fetch`` / ``XHR`` / WS
  handshakes, so this catches the entire browser-attack class.
* If the ``Origin`` header is missing on a *read* (GET / HEAD / OPTIONS), the
  request is allowed through. That covers ``curl``, the MCP client (Claude
  Code, etc.), and top-level browser navigation — none of which can read
  response bodies cross-origin from page JS, so they pose no exfiltration risk.
* If the ``Origin`` header is missing on a *mutating* method (POST / PUT /
  DELETE / PATCH) and ``require_origin_methods`` lists that method, the request
  is rejected. Modern browsers always attach ``Origin`` to mutating requests;
  fail-closed here closes off the historical "form POST without Origin" CSRF
  shape, with CSRF tokens layered behind it as defense in depth.

The allow-list is path-scoped via ``protected_path_prefixes`` so static page
templates, the OAuth callback landing, and ``/health`` aren't affected.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

logger = logging.getLogger(__name__)


def default_localhost_origins(port: int) -> list[str]:
    """Origins corresponding to the dashboard URL on a localhost install."""
    return [
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    ]


class OriginMiddleware:
    """Pure ASGI middleware: rejects cross-origin requests to protected paths."""

    def __init__(
        self,
        app,
        allowed_origins: Iterable[str],
        protected_path_prefixes: Iterable[str] = ("/api/", "/ws/"),
        require_origin_methods: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)
        self.protected_path_prefixes = tuple(protected_path_prefixes)
        self.require_origin_methods = frozenset(
            m.upper() for m in require_origin_methods
        )

    async def __call__(self, scope, receive, send):
        scope_type = scope.get("type")
        if scope_type not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return

        if not self._is_protected(scope.get("path", "")):
            await self.app(scope, receive, send)
            return

        origin = _get_header(scope, b"origin")
        method = scope.get("method", "").upper() if scope_type == "http" else ""

        if origin is None:
            if scope_type == "http" and method in self.require_origin_methods:
                logger.warning(
                    "Origin-required: http %s %s (no Origin header)",
                    method,
                    scope.get("path", ""),
                )
                await _send_http_forbidden(send)
                return
            await self.app(scope, receive, send)
            return

        if origin in self.allowed_origins:
            await self.app(scope, receive, send)
            return

        logger.warning(
            "Origin-blocked: %s %s origin=%r",
            scope_type,
            scope.get("path", ""),
            origin,
        )
        if scope_type == "http":
            await _send_http_forbidden(send)
        else:
            await _reject_websocket(receive, send)

    def _is_protected(self, path: str) -> bool:
        return any(path.startswith(p) for p in self.protected_path_prefixes)


def _get_header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v.decode("latin-1")
    return None


async def _send_http_forbidden(send) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": b'{"error":"Origin not allowed"}',
        }
    )


async def _reject_websocket(receive, send) -> None:
    """Consume the handshake event and close with a 4403 application code."""
    msg = await receive()
    if msg.get("type") == "websocket.connect":
        await send({"type": "websocket.close", "code": 4403})
