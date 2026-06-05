"""Spec-compliant MCP / OAuth discovery primitives.

Implements the MCP authorization spec's discovery flow:

  1. Probe the MCP URL.
  2. On 401, parse the `WWW-Authenticate` header for a `resource_metadata`
     parameter (RFC 9728 / OAuth 2.0 Protected Resource Metadata).
  3. Fetch the protected resource metadata, read `authorization_servers`.
  4. Fetch the authorization server's metadata at
     `<issuer>/.well-known/oauth-authorization-server` (with OIDC fallback).

A legacy "guess the issuer from the MCP host" fallback is kept for servers
that don't advertise `WWW-Authenticate` (e.g. early MCP implementations
where the OAuth server and the MCP endpoint share a host).
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 10.0


# RFC 6750 §3 lets `resource_metadata` appear as either a quoted-string or
# an unquoted token. We only need to extract the value, not validate the
# whole challenge grammar — a focused regex is enough and robust.
_RESOURCE_METADATA_RE = re.compile(
    r'resource_metadata\s*=\s*(?:"([^"]+)"|([^\s,]+))',
    re.IGNORECASE,
)

# RFC 6750 §3: WWW-Authenticate may carry a `scope` attribute listing the
# scopes required for the resource. Value grammar is RFC 6749 §3.3:
# space-delimited, case-sensitive tokens. The attribute name is
# case-insensitive (RFC 7235); the *value* is case-sensitive and preserved
# verbatim by the regex (IGNORECASE only affects matching, not capture).
_SCOPE_RE = re.compile(
    r'scope\s*=\s*(?:"([^"]*)"|([^\s,]+))',
    re.IGNORECASE,
)


def issuer_matches(requested: str, claimed: str | None) -> bool:
    """RFC 8414 §3.3 issuer-identity check.

    The AS metadata's `issuer` MUST be identical to the issuer URL into
    which the well-known segment was inserted to retrieve the metadata.
    Comparison is exact after stripping a single trailing slash. When the
    server omits the `issuer` field there is nothing to validate against,
    and we let the caller decide what to do — returning True here keeps
    the legacy lenient behaviour for servers that don't advertise it at
    all (Pinging metadata without an issuer line is rare but not a spec
    violation worth rejecting on its own).
    """
    if not claimed:
        return True
    return requested.rstrip("/") == claimed.rstrip("/")


def wellknown_metadata_urls(issuer: str, kind: str) -> list[str]:
    """Return well-known metadata URLs for `issuer` in priority order.

    Per RFC 8414 §3.1, when the issuer has a non-empty path the well-known
    URI string MUST be inserted between the host and the path — e.g. for
    issuer ``https://access.stripe.com/mcp`` the spec form is
    ``https://access.stripe.com/.well-known/oauth-authorization-server/mcp``,
    not ``…/mcp/.well-known/…``. Some non-compliant servers serve the
    appended form instead, so we return the spec form first and the
    appended form as a fallback. For root-path issuers the two forms are
    identical and we return a single URL.
    """
    issuer = issuer.rstrip("/")
    suffix = f"/.well-known/{kind}"
    parsed = urlparse(issuer)
    if not parsed.path:
        return [f"{issuer}{suffix}"]
    base = f"{parsed.scheme}://{parsed.netloc}"
    return [f"{base}{suffix}{parsed.path}", f"{issuer}{suffix}"]


def extract_resource_metadata_url(www_authenticate: str) -> str | None:
    """Return the `resource_metadata` URL from a WWW-Authenticate header, or None."""
    if not www_authenticate:
        return None
    m = _RESOURCE_METADATA_RE.search(www_authenticate)
    if not m:
        return None
    return m.group(1) or m.group(2)


def extract_scope_from_www_authenticate(www_authenticate: str) -> list[str] | None:
    """Return scope tokens from a WWW-Authenticate header, or None if absent.

    Per RFC 6749 §3.3, scope values are space-delimited, case-sensitive
    tokens. Per RFC 6750 §3, an MCP / OAuth resource server SHOULD include
    this attribute on a 401 to indicate which scopes the access token must
    cover for this request. Returns None when the attribute is absent so the
    caller can distinguish "no signal" from "signal saying no scopes".
    """
    if not www_authenticate:
        return None
    m = _SCOPE_RE.search(www_authenticate)
    if not m:
        return None
    value = m.group(1) if m.group(1) is not None else m.group(2)
    if not value:
        return []
    return value.split()


async def probe_mcp_for_www_authenticate(
    mcp_url: str, timeout: float = DEFAULT_TIMEOUT
) -> tuple[str | None, list[str] | None]:
    """Probe the MCP URL and return the bits we care about from WWW-Authenticate.

    Tries GET first (cheap, no body), then falls back to a POST initialize
    JSON-RPC request, since some MCP servers only run the auth filter on
    POSTs that look like protocol traffic.

    Returns `(resource_metadata_url, scope_tokens)`:
    - `resource_metadata_url` is the URL exactly as the server emitted it —
      preserving any query string (Supabase encodes its `project_ref` here,
      and the query is part of the resource identifier).
    - `scope_tokens` is the parsed RFC 6749 §3.3 token list from the `scope`
      attribute if present, else None.

    Returns `(None, None)` if the probe never sees a 401, or if neither
    attribute is present on the 401 we do see.
    """
    headers = {"Accept": "application/json, text/event-stream"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        # 1) GET probe
        try:
            resp = await client.get(mcp_url, headers=headers)
            if resp.status_code == 401:
                header = resp.headers.get("WWW-Authenticate", "")
                url = extract_resource_metadata_url(header)
                scopes = extract_scope_from_www_authenticate(header)
                if url or scopes is not None:
                    return url, scopes
        except httpx.HTTPError as e:
            logger.debug(f"GET probe of {mcp_url} failed: {e}")

        # 2) POST initialize probe
        init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "openmaskit-discovery", "version": "1.0"},
            },
        }
        try:
            resp = await client.post(
                mcp_url,
                json=init_body,
                headers={**headers, "Content-Type": "application/json"},
            )
            if resp.status_code == 401:
                header = resp.headers.get("WWW-Authenticate", "")
                url = extract_resource_metadata_url(header)
                scopes = extract_scope_from_www_authenticate(header)
                if url or scopes is not None:
                    return url, scopes
        except httpx.HTTPError as e:
            logger.debug(f"POST probe of {mcp_url} failed: {e}")

    return None, None


async def fetch_protected_resource_metadata(
    url: str, timeout: float = DEFAULT_TIMEOUT
) -> dict | None:
    """Fetch RFC 9728 Protected Resource Metadata."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        try:
            logger.info(f"Fetching protected resource metadata at {url}")
            resp = await client.get(url)
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(f"Failed to fetch protected resource metadata at {url}: {e}")
            return None


async def fetch_oauth_server_metadata(
    issuer: str, timeout: float = DEFAULT_TIMEOUT
) -> dict | None:
    """Fetch OAuth 2.0 authorization server metadata for `issuer`.

    Tries `.well-known/oauth-authorization-server` first (the spec for OAuth
    2.0 AS metadata, RFC 8414), then falls back to OIDC discovery at
    `.well-known/openid-configuration`. Merges results when both succeed,
    preferring OAuth 2.0 endpoints for OAuth fields and OIDC for OIDC fields.
    """
    issuer = issuer.rstrip("/")
    oauth_meta: dict | None = None
    oidc_meta: dict | None = None

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
        for oauth_url in wellknown_metadata_urls(issuer, "oauth-authorization-server"):
            try:
                logger.info(f"Fetching OAuth 2.0 AS metadata at {oauth_url}")
                resp = await client.get(oauth_url)
                resp.raise_for_status()
                candidate = resp.json()
            except Exception as e:
                logger.debug(f"OAuth 2.0 AS metadata fetch failed at {oauth_url}: {e}")
                continue
            if not issuer_matches(issuer, candidate.get("issuer")):
                logger.warning(
                    f"AS metadata at {oauth_url} claims issuer "
                    f"{candidate.get('issuer')!r}, expected {issuer!r} (RFC 8414 §3.3); "
                    "skipping this candidate"
                )
                continue
            oauth_meta = candidate
            break

        for oidc_url in wellknown_metadata_urls(issuer, "openid-configuration"):
            try:
                logger.info(f"Fetching OIDC metadata at {oidc_url}")
                resp = await client.get(oidc_url)
                resp.raise_for_status()
                candidate = resp.json()
            except Exception as e:
                logger.debug(f"OIDC metadata fetch failed at {oidc_url}: {e}")
                continue
            if not issuer_matches(issuer, candidate.get("issuer")):
                logger.warning(
                    f"OIDC metadata at {oidc_url} claims issuer "
                    f"{candidate.get('issuer')!r}, expected {issuer!r} (RFC 8414 §3.3); "
                    "skipping this candidate"
                )
                continue
            oidc_meta = candidate
            break

    if not oauth_meta and not oidc_meta:
        return None

    merged: dict = {}
    if oidc_meta:
        merged.update(oidc_meta)
    if oauth_meta:
        # OAuth 2.0 fields take precedence for OAuth concerns
        merged.update(oauth_meta)
        # Specifically prefer OIDC's authorization/token endpoints only when
        # OAuth 2.0 metadata omits them (rare; usually both list them).
        for key in ("authorization_endpoint", "token_endpoint"):
            if not merged.get(key) and oidc_meta and oidc_meta.get(key):
                merged[key] = oidc_meta[key]
    return merged


async def discover_via_mcp_probe(mcp_url: str) -> dict | None:
    """Spec-compliant discovery: probe MCP → PRM → AS metadata.

    Returns None if any step fails — caller can then fall back to
    `discover_legacy`.
    """
    prm_url, www_auth_scopes = await probe_mcp_for_www_authenticate(mcp_url)
    if not prm_url:
        return None

    prm = await fetch_protected_resource_metadata(prm_url)
    if not prm:
        return None

    auth_servers = prm.get("authorization_servers") or []
    if not auth_servers:
        logger.warning(
            f"Protected resource metadata at {prm_url} has no authorization_servers"
        )
        return None
    if len(auth_servers) > 1:
        logger.info(
            f"Protected resource metadata lists {len(auth_servers)} authorization servers; "
            f"using first: {auth_servers[0]}"
        )

    issuer = auth_servers[0].rstrip("/")
    server_meta = await fetch_oauth_server_metadata(issuer)
    if not server_meta:
        return None

    # Scope priority: RFC 6750 §3 `scope` attribute from the 401 challenge
    # (the MCP spec frames this as "the scopes required for accessing the
    # resource" — most direct, live, and resource-specific) → PRM
    # `scopes_supported` (broader catalog of scopes used at this resource) →
    # AS-wide `scopes_supported` (least specific) → empty list as last
    # resort. WWW-Authenticate wins because when the server bothers to emit
    # it, the MCP spec says it's the authoritative signal of what the client
    # actually needs.
    scopes = (
        www_auth_scopes
        or prm.get("scopes_supported")
        or server_meta.get("scopes_supported")
        or []
    )

    return {
        "issuer": server_meta.get("issuer", issuer),
        "mcp_url": mcp_url,
        "authorization_endpoint": server_meta.get("authorization_endpoint"),
        "token_endpoint": server_meta.get("token_endpoint"),
        "registration_endpoint": server_meta.get("registration_endpoint"),
        "scopes_supported": scopes,
        "resource": prm.get("resource"),
        "resource_metadata_url": prm_url,
        "discovery_method": "mcp_probe",
    }


async def discover_legacy(mcp_url: str) -> dict | None:
    """Host-derived discovery for servers that don't advertise WWW-Authenticate.

    Treats `<scheme>://<host>` of the MCP URL as the OAuth issuer, then runs
    the same AS metadata fetch + (optional) protected resource lookup as the
    original implementation. Kept for backwards compatibility with servers
    like GitLab that predate the WWW-Authenticate flow.
    """
    parsed = urlparse(mcp_url)
    if not parsed.scheme or not parsed.netloc:
        return None
    issuer = f"{parsed.scheme}://{parsed.netloc}"

    server_meta = await fetch_oauth_server_metadata(issuer)
    if not server_meta:
        return None

    # Best-effort PRM lookup. SEP-985 / RFC 9728: try the path-based
    # well-known first (if the MCP URL has a path), then fall back to the
    # root-based well-known. Both are spec-compliant locations; we tried
    # neither historically when there was no path.
    prm: dict | None = None
    prm_url: str | None = None
    if parsed.path:
        candidate = f"{issuer}/.well-known/oauth-protected-resource/{parsed.path.lstrip('/')}"
        prm = await fetch_protected_resource_metadata(candidate)
        if prm:
            prm_url = candidate
    if not prm:
        candidate = f"{issuer}/.well-known/oauth-protected-resource"
        prm = await fetch_protected_resource_metadata(candidate)
        if prm:
            prm_url = candidate

    scopes = (
        (prm.get("scopes_supported") if prm else None)
        or server_meta.get("scopes_supported")
        or []
    )

    return {
        "issuer": server_meta.get("issuer", issuer),
        "mcp_url": mcp_url,
        "authorization_endpoint": server_meta.get("authorization_endpoint"),
        "token_endpoint": server_meta.get("token_endpoint"),
        "registration_endpoint": server_meta.get("registration_endpoint"),
        "scopes_supported": scopes,
        "resource": prm.get("resource") if prm else None,
        "resource_metadata_url": prm_url,
        "discovery_method": "legacy_host" + ("+resource" if prm else ""),
    }


async def discover(mcp_url: str) -> dict | None:
    """Top-level discovery: try the MCP probe flow first, fall back to legacy."""
    result = await discover_via_mcp_probe(mcp_url)
    if result:
        return result
    logger.info(
        f"MCP probe discovery did not succeed for {mcp_url}; falling back to legacy host discovery"
    )
    return await discover_legacy(mcp_url)
