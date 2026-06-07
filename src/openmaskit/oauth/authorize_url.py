"""OAuth 2.1 authorize-URL construction with PKCE.

Implements just enough of RFC 6749 §4.1.1 (authorization request) and RFC 7636
(PKCE, S256) to let OpenMaskit build the URL itself instead of delegating to
the MCP SDK's `OAuthClientProvider`. The SDK still owns runtime refresh, but
the install-time browser redirect now originates from our own code so the FE
can drive a same-tab navigation.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from urllib.parse import urlencode


def generate_pkce() -> tuple[str, str]:
    """Return ``(code_verifier, code_challenge)`` for PKCE S256.

    Per RFC 7636 §4.1 the verifier is a high-entropy URL-safe string of 43-128
    characters; we use 64 bytes of randomness which encodes to 86 base64url
    characters — comfortably above the minimum and within the maximum.
    """
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return code_verifier, code_challenge


def build_authorize_url(
    authorization_endpoint: str,
    *,
    client_id: str,
    redirect_uri: str,
    scope: str,
    state: str,
    code_challenge: str,
    resource: str | None = None,
) -> str:
    """Assemble an RFC 6749 §4.1.1 authorize URL with PKCE S256.

    ``scope`` is included only when non-empty so we don't send ``scope=`` to
    authorization servers that reject empty values. ``resource`` is the
    RFC 8707 §2 resource indicator — when provided, the AS binds the issued
    access token to that resource so the protected resource server accepts it.
    The MCP authorization spec requires this when protected-resource metadata
    advertises a ``resource``; without it, providers like Slack issue tokens
    whose audience is the AS's home (e.g. ``slack.com``) and the MCP endpoint
    (``mcp.slack.com``) rejects the request.
    """
    params: dict[str, str] = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    if scope:
        params["scope"] = scope
    if resource:
        params["resource"] = resource

    sep = "&" if "?" in authorization_endpoint else "?"
    return f"{authorization_endpoint}{sep}{urlencode(params)}"
