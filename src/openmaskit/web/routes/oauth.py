"""OAuth-related API routes for discovery and dynamic client registration."""

import logging
from urllib.parse import urlparse

from starlette.requests import Request
from starlette.responses import JSONResponse

from openmaskit.oauth import discovery

logger = logging.getLogger(__name__)


async def discover_oauth_metadata(request: Request):
    """Discover OAuth endpoints for a given MCP server URL.

    Runs the spec-compliant flow first: probe the MCP URL for a
    `WWW-Authenticate` header, follow its `resource_metadata` link to the
    protected resource metadata, then fetch the listed authorization
    server's metadata. Falls back to host-derived discovery for servers
    that don't advertise `WWW-Authenticate`.

    POST /api/oauth/discover
    Body: {"url": "https://mcp.example.com/mcp"}

    Returns: discovery metadata + the issuer the user should authenticate
    against (which may differ from the MCP URL's host).
    """
    body = await request.json()
    url = (body.get("url") or "").strip()

    if not url:
        return JSONResponse({"detail": "MCP URL is required"}, status_code=400)

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return JSONResponse(
                {"detail": "Invalid URL format. Must include scheme and host."},
                status_code=400,
            )
    except Exception as e:
        logger.error(f"Failed to parse URL: {e}")
        return JSONResponse({"detail": f"Invalid URL format: {e}"}, status_code=400)

    result = await discovery.discover(url)
    if not result:
        return JSONResponse(
            {
                "detail": (
                    f"Discovery failed for {url}. The server may not support OAuth, "
                    "or the URL may be incorrect."
                )
            },
            status_code=400,
        )

    if not result.get("registration_endpoint"):
        logger.warning(
            f"Discovery for {url} succeeded but the authorization server does not advertise "
            "a registration_endpoint; dynamic client registration will not be possible."
        )

    return JSONResponse(result)
