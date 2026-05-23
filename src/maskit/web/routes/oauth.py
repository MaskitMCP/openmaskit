"""OAuth-related API routes for discovery and dynamic client registration."""

from starlette.requests import Request
from starlette.responses import JSONResponse
import httpx
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


async def discover_oauth_metadata(request: Request):
    """
    Discover OAuth/OIDC endpoints from MCP URL.
    Extracts issuer (scheme + host) from the full MCP URL for discovery.

    POST /api/oauth/discover
    Body: {"url": "https://gitlab.com/api/v4/mcp"}

    Returns: Discovery metadata + extracted issuer
    """
    body = await request.json()
    url = body.get("url", "")

    if not url:
        return JSONResponse({"detail": "MCP URL is required"}, status_code=400)

    # Extract issuer from URL (scheme + host)
    try:
        parsed = urlparse(url)
        issuer = f"{parsed.scheme}://{parsed.netloc}"

        if not issuer or not parsed.scheme or not parsed.netloc:
            return JSONResponse(
                {"detail": "Invalid URL format. Must include scheme and host."},
                status_code=400
            )
    except Exception as e:
        logger.error(f"Failed to parse URL: {e}")
        return JSONResponse(
            {"detail": f"Invalid URL format: {str(e)}"},
            status_code=400
        )

    # Try OIDC discovery first
    oidc_url = f"{issuer}/.well-known/openid-configuration"
    oidc_metadata = None

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            logger.info(f"Attempting OIDC discovery at {oidc_url}")
            resp = await client.get(oidc_url)
            resp.raise_for_status()
            oidc_metadata = resp.json()
            logger.info(f"OIDC discovery successful for {issuer}")

            # If OIDC has registration_endpoint, we're done
            if oidc_metadata.get("registration_endpoint"):
                return JSONResponse({
                    "issuer": oidc_metadata.get("issuer", issuer),
                    "mcp_url": url,
                    "authorization_endpoint": oidc_metadata["authorization_endpoint"],
                    "token_endpoint": oidc_metadata["token_endpoint"],
                    "registration_endpoint": oidc_metadata["registration_endpoint"],
                    "scopes_supported": oidc_metadata.get("scopes_supported", []),
                    "discovery_method": "oidc"
                })
            else:
                logger.info(f"OIDC response lacks registration_endpoint, will try OAuth 2.0 discovery")

        except Exception as e:
            logger.warning(f"OIDC discovery failed for {issuer}: {e}")

    # Try OAuth 2.0 Protected Resource Metadata (RFC 8707) for resource-specific scopes
    # This is used by Atlassian and other services that have resource-specific scopes
    resource_metadata = None
    if parsed.path:  # Only if there's a path in the URL
        resource_path = parsed.path.lstrip('/')
        resource_url = f"{issuer}/.well-known/oauth-protected-resource/{resource_path}"

        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                logger.info(f"Attempting OAuth Protected Resource discovery at {resource_url}")
                resp = await client.get(resource_url)
                resp.raise_for_status()
                resource_metadata = resp.json()
                logger.info(f"OAuth Protected Resource discovery successful for {issuer}")
            except Exception as e:
                logger.debug(f"OAuth Protected Resource discovery failed for {issuer}: {e}")

    # Try OAuth 2.0 discovery (either as fallback or to get registration_endpoint)
    oauth_url = f"{issuer}/.well-known/oauth-authorization-server"

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            logger.info(f"Attempting OAuth 2.0 discovery at {oauth_url}")
            resp = await client.get(oauth_url)
            resp.raise_for_status()
            oauth_metadata = resp.json()

            logger.info(f"OAuth 2.0 discovery successful for {issuer}")

            # Merge all discovered metadata
            # Priority for scopes: resource_metadata > oidc_metadata > oauth_metadata
            scopes = []
            if resource_metadata and resource_metadata.get("scopes_supported"):
                scopes = resource_metadata["scopes_supported"]
            elif oidc_metadata and oidc_metadata.get("scopes_supported"):
                scopes = oidc_metadata["scopes_supported"]
            else:
                scopes = oauth_metadata.get("scopes_supported", [])

            # If we have OIDC metadata, merge it with OAuth 2.0
            if oidc_metadata:
                return JSONResponse({
                    "issuer": oidc_metadata.get("issuer", issuer),
                    "mcp_url": url,
                    "authorization_endpoint": oidc_metadata["authorization_endpoint"],
                    "token_endpoint": oidc_metadata["token_endpoint"],
                    "registration_endpoint": oauth_metadata.get("registration_endpoint"),  # From OAuth 2.0
                    "scopes_supported": scopes,
                    "discovery_method": "oidc+oauth2+resource" if resource_metadata else "oidc+oauth2"
                })
            else:
                # Only OAuth 2.0 succeeded
                return JSONResponse({
                    "issuer": oauth_metadata.get("issuer", issuer),
                    "mcp_url": url,
                    "authorization_endpoint": oauth_metadata["authorization_endpoint"],
                    "token_endpoint": oauth_metadata["token_endpoint"],
                    "registration_endpoint": oauth_metadata.get("registration_endpoint"),
                    "scopes_supported": scopes,
                    "discovery_method": "oauth2+resource" if resource_metadata else "oauth2"
                })

        except Exception as e:
            # If OAuth 2.0 also failed, check if we at least have OIDC metadata
            if oidc_metadata:
                logger.warning(f"OAuth 2.0 discovery failed, but OIDC succeeded. Returning OIDC data without registration_endpoint")

                # Still prefer resource scopes if available
                scopes = []
                if resource_metadata and resource_metadata.get("scopes_supported"):
                    scopes = resource_metadata["scopes_supported"]
                else:
                    scopes = oidc_metadata.get("scopes_supported", [])

                return JSONResponse({
                    "issuer": oidc_metadata.get("issuer", issuer),
                    "mcp_url": url,
                    "authorization_endpoint": oidc_metadata["authorization_endpoint"],
                    "token_endpoint": oidc_metadata["token_endpoint"],
                    "registration_endpoint": None,  # Explicitly None
                    "scopes_supported": scopes,
                    "discovery_method": "oidc+resource" if resource_metadata else "oidc"
                })

            logger.error(f"Both OIDC and OAuth 2.0 discovery failed for {issuer}: {e}")
            return JSONResponse(
                {"detail": f"Discovery failed for {issuer}. The server may not support OAuth discovery, or the URL may be incorrect."},
                status_code=400
            )
