"""Direct OAuth 2.1 authorization-code exchange.

POSTs to the AS's ``token_endpoint`` per RFC 6749 §4.1.3 + RFC 7636 §4.5
(PKCE ``code_verifier``). Supports the three client-auth methods OpenMaskit
encounters in the wild: ``client_secret_post``, ``client_secret_basic``, and
``none`` (PKCE-only public clients).
"""

from __future__ import annotations

import base64
import logging
from typing import Literal

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0

AuthMethod = Literal["client_secret_post", "client_secret_basic", "none"]


async def exchange_code(
    token_endpoint: str,
    *,
    code: str,
    redirect_uri: str,
    client_id: str,
    code_verifier: str,
    client_secret: str | None = None,
    auth_method: AuthMethod = "client_secret_post",
    resource: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict:
    """Exchange an authorization code for tokens.

    Returns the parsed token response (``access_token``, ``token_type``,
    ``scope``, ``expires_in``, ``refresh_token``). Raises ``RuntimeError``
    on any failure, surfacing the AS's RFC 6749 §5.2 ``error`` /
    ``error_description`` fields verbatim so install-time UI errors are
    diagnostic instead of generic.

    ``resource`` is the RFC 8707 §2 resource indicator. It MUST match the
    value sent on the authorize request so the AS issues a token bound to
    the same resource server.
    """
    body: dict[str, str] = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": code_verifier,
    }
    if resource:
        body["resource"] = resource
    headers: dict[str, str] = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
    }

    if auth_method == "client_secret_post":
        if client_secret:
            body["client_secret"] = client_secret
    elif auth_method == "client_secret_basic":
        if not client_secret:
            raise RuntimeError(
                "client_secret_basic auth requires a client_secret"
            )
        creds = f"{client_id}:{client_secret}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(creds).decode("ascii")
    elif auth_method == "none":
        pass
    else:  # pragma: no cover - typing prevents this branch in practice
        raise RuntimeError(f"Unsupported auth_method: {auth_method}")

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.post(token_endpoint, data=body, headers=headers)
        except httpx.HTTPError as e:
            msg = f"Token exchange network error at {token_endpoint}: {e}"
            logger.error(msg)
            raise RuntimeError(msg) from e

        if 200 <= resp.status_code < 300:
            try:
                return resp.json()
            except ValueError as e:
                raise RuntimeError(
                    f"Token endpoint returned {resp.status_code} but body was not JSON: {e}"
                ) from e

        error_code: str | None = None
        error_description: str | None = None
        body_snippet = ""
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                error_code = payload.get("error")
                error_description = payload.get("error_description")
        except ValueError:
            body_snippet = resp.text[:200].strip()

        parts = [f"Token endpoint {token_endpoint} rejected exchange ({resp.status_code}"]
        if error_code:
            parts[0] += f" {error_code})"
        else:
            parts[0] += ")"
        if error_description:
            parts.append(f": {error_description}")
        elif body_snippet:
            parts.append(f": {body_snippet}")

        msg = "".join(parts)
        logger.error(msg)
        raise RuntimeError(msg)
