"""CSRF token middleware for the dashboard API.

OpenMaskit's dashboard binds to localhost on the user's own machine, and the
``OriginMiddleware`` already rejects cross-origin fetches that carry an
``Origin`` header. Two gaps remain:

* Browsers do not always attach ``Origin`` to top-level form POSTs, and some
  older / non-spec-compliant clients omit it on AJAX as well. ``OriginMiddleware``
  separately fails *closed* on missing-Origin for mutating methods, but a CSRF
  token is the canonical second line of defense: even if a request reaches the
  app with no ``Origin``, it cannot mutate state without a token only same-origin
  JS could have read.
* Defense in depth. If the Origin allow-list is ever misconfigured (e.g.
  ``OPENMASKIT_ALLOWED_ORIGINS`` widened to include a domain the attacker
  controls), the CSRF token still keeps mutations gated.

The token is a per-process random string, fetched once by the dashboard from
``GET /api/csrf`` and replayed as ``X-CSRF-Token`` on every mutating request.
Validation is constant-time. Read methods (GET/HEAD/OPTIONS) and non-``/api/``
paths are not gated.
"""

from __future__ import annotations

import logging
import secrets
from collections.abc import Iterable

logger = logging.getLogger(__name__)

_MUTATING_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})


def generate_csrf_token() -> str:
    """Return a fresh random token suitable for use as a CSRF secret."""
    return secrets.token_urlsafe(32)


class CsrfMiddleware:
    """Pure ASGI middleware: rejects mutating requests without a valid CSRF token."""

    def __init__(
        self,
        app,
        token: str,
        protected_path_prefixes: Iterable[str] = ("/api/",),
    ) -> None:
        if not token:
            raise ValueError("CsrfMiddleware requires a non-empty token")
        self.app = app
        self.token = token
        self.protected_path_prefixes = tuple(protected_path_prefixes)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "").upper()
        if method not in _MUTATING_METHODS:
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if not any(path.startswith(p) for p in self.protected_path_prefixes):
            await self.app(scope, receive, send)
            return

        supplied = _get_header(scope, b"x-csrf-token")
        if supplied is None or not secrets.compare_digest(supplied, self.token):
            logger.warning("CSRF-blocked: %s %s", method, path)
            await _send_csrf_forbidden(send)
            return

        await self.app(scope, receive, send)


def _get_header(scope, name: bytes) -> str | None:
    for k, v in scope.get("headers", []):
        if k.lower() == name:
            return v.decode("latin-1")
    return None


async def _send_csrf_forbidden(send) -> None:
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
            "body": b'{"error":"csrf_invalid"}',
        }
    )
