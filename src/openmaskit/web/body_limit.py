"""Body-size cap middleware for the HTTP endpoints.

Both the dashboard API (:9473/api/*) and the MCP HTTP endpoint (:9474) read
their entire request body into memory before any handler runs. Without a cap,
a buggy or hostile caller can force OpenMaskit to allocate arbitrary memory by
sending — or *claiming* to send — a huge body.

This middleware enforces a max in two layers:

1. If the ``Content-Length`` header is present and exceeds the cap, reject
   with 413 before reading anything.
2. Otherwise buffer the body while counting *actual* bytes received and
   reject with 413 if the total goes over. Catches clients that lie about
   ``Content-Length`` or omit it entirely (chunked transfer).

On success, the buffered body is replayed to the downstream app via a wrapped
``receive`` callable, so handlers see the request exactly as if the middleware
weren't there.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

DEFAULT_MAX_REQUEST_BYTES = 1024 * 1024  # 1 MiB


def get_max_request_bytes() -> int:
    """Return the configured body-size cap, in bytes.

    Reads ``OPENMASKIT_MAX_REQUEST_BYTES`` from the environment; falls back to
    ``DEFAULT_MAX_REQUEST_BYTES`` if unset, non-numeric, or non-positive.
    """
    raw = os.environ.get("OPENMASKIT_MAX_REQUEST_BYTES")
    if raw is None:
        return DEFAULT_MAX_REQUEST_BYTES
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "Ignoring non-numeric OPENMASKIT_MAX_REQUEST_BYTES=%r; using default %d",
            raw,
            DEFAULT_MAX_REQUEST_BYTES,
        )
        return DEFAULT_MAX_REQUEST_BYTES
    if value <= 0:
        logger.warning(
            "Ignoring non-positive OPENMASKIT_MAX_REQUEST_BYTES=%d; using default %d",
            value,
            DEFAULT_MAX_REQUEST_BYTES,
        )
        return DEFAULT_MAX_REQUEST_BYTES
    return value


class BodySizeLimitMiddleware:
    """Pure ASGI middleware: reject HTTP requests whose body exceeds a cap."""

    def __init__(self, app, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            logger.warning(
                "Body-too-large (Content-Length=%d > max=%d): %s %s",
                declared,
                self.max_bytes,
                scope.get("method", ""),
                scope.get("path", ""),
            )
            await _send_413(send, self.max_bytes)
            return

        body_parts: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            mtype = message.get("type")
            if mtype == "http.disconnect":
                # Client gave up before sending; let the downstream app see
                # the disconnect by replaying an empty body. Most handlers
                # will produce a 4xx on parse error, which is fine.
                break
            if mtype != "http.request":
                # Unknown ASGI message — pass through unchanged.
                continue
            chunk = message.get("body", b"") or b""
            total += len(chunk)
            if total > self.max_bytes:
                logger.warning(
                    "Body-too-large (read=%d > max=%d): %s %s",
                    total,
                    self.max_bytes,
                    scope.get("method", ""),
                    scope.get("path", ""),
                )
                await _send_413(send, self.max_bytes)
                # Drain the rest so the client sees the response instead of
                # a connection reset.
                if message.get("more_body", False):
                    await _drain(receive)
                return
            body_parts.append(chunk)
            if not message.get("more_body", False):
                break

        await self.app(scope, _replay_receive(body_parts), send)


def _content_length(scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() == b"content-length":
            try:
                return int(value.decode("latin-1"))
            except (ValueError, AttributeError):
                return None
    return None


def _replay_receive(body_parts: list[bytes]):
    iterator = iter(body_parts)
    finished = False

    async def receive():
        nonlocal finished
        try:
            chunk = next(iterator)
            return {"type": "http.request", "body": chunk, "more_body": True}
        except StopIteration:
            if not finished:
                finished = True
                return {"type": "http.request", "body": b"", "more_body": False}
            # Some ASGI apps may call receive() again after final; return a
            # terminal empty message rather than blocking.
            return {"type": "http.request", "body": b"", "more_body": False}

    return receive


async def _drain(receive) -> None:
    while True:
        msg = await receive()
        if msg.get("type") == "http.disconnect":
            return
        if msg.get("type") == "http.request" and not msg.get("more_body", False):
            return


async def _send_413(send, max_bytes: int) -> None:
    body = (
        '{"error":"request_too_large","max_bytes":' + str(max_bytes) + "}"
    ).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})
