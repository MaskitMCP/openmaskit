"""Tests for the MCP / OAuth discovery primitives."""

from __future__ import annotations

import httpx
import pytest
import respx

from openmaskit.oauth import discovery


class TestExtractResourceMetadata:
    def test_quoted_value(self):
        header = 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        url = discovery.extract_resource_metadata_url(header)
        assert url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    def test_quoted_value_preserves_query_string(self):
        header = 'Bearer resource_metadata="https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc123"'
        url = discovery.extract_resource_metadata_url(header)
        assert url == "https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc123"

    def test_unquoted_value(self):
        header = "Bearer resource_metadata=https://example.com/prm"
        url = discovery.extract_resource_metadata_url(header)
        assert url == "https://example.com/prm"

    def test_with_other_params(self):
        header = 'Bearer error="invalid_token", resource_metadata="https://example.com/prm", scope="read"'
        url = discovery.extract_resource_metadata_url(header)
        assert url == "https://example.com/prm"

    def test_case_insensitive_param_name(self):
        header = 'Bearer Resource_Metadata="https://example.com/prm"'
        url = discovery.extract_resource_metadata_url(header)
        assert url == "https://example.com/prm"

    def test_returns_none_when_absent(self):
        assert discovery.extract_resource_metadata_url("Bearer realm=\"x\"") is None

    def test_returns_none_for_empty_header(self):
        assert discovery.extract_resource_metadata_url("") is None
        assert discovery.extract_resource_metadata_url(None) is None  # type: ignore[arg-type]


class TestProbeMcpForResourceMetadata:
    @pytest.mark.anyio
    @respx.mock
    async def test_get_returns_401_with_resource_metadata(self):
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        url = await discovery.probe_mcp_for_resource_metadata("https://mcp.example.com/mcp")
        assert url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    @pytest.mark.anyio
    @respx.mock
    async def test_get_preserves_query_string_in_resource_metadata_url(self):
        respx.get("https://mcp.supabase.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc"'
                },
            )
        )
        url = await discovery.probe_mcp_for_resource_metadata("https://mcp.supabase.com/mcp")
        assert url == "https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc"

    @pytest.mark.anyio
    @respx.mock
    async def test_falls_back_to_post_when_get_lacks_header(self):
        respx.get("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        respx.post("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/prm"'
                },
            )
        )
        url = await discovery.probe_mcp_for_resource_metadata("https://mcp.example.com/mcp")
        assert url == "https://mcp.example.com/prm"

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_no_www_authenticate(self):
        respx.get("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        respx.post("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        url = await discovery.probe_mcp_for_resource_metadata("https://mcp.example.com/mcp")
        assert url is None

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_on_network_error(self):
        respx.get("https://nope.example.com/mcp").mock(side_effect=httpx.ConnectError("boom"))
        respx.post("https://nope.example.com/mcp").mock(side_effect=httpx.ConnectError("boom"))
        url = await discovery.probe_mcp_for_resource_metadata("https://nope.example.com/mcp")
        assert url is None


class TestFetchOauthServerMetadata:
    @pytest.mark.anyio
    @respx.mock
    async def test_oauth_authorization_server(self):
        meta = {
            "issuer": "https://api.example.com",
            "authorization_endpoint": "https://api.example.com/oauth/authorize",
            "token_endpoint": "https://api.example.com/oauth/token",
            "registration_endpoint": "https://api.example.com/oauth/register",
        }
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json=meta)
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        result = await discovery.fetch_oauth_server_metadata("https://api.example.com")
        assert result is not None
        assert result["authorization_endpoint"] == "https://api.example.com/oauth/authorize"
        assert result["registration_endpoint"] == "https://api.example.com/oauth/register"

    @pytest.mark.anyio
    @respx.mock
    async def test_oidc_fallback(self):
        oidc = {
            "issuer": "https://idp.example.com",
            "authorization_endpoint": "https://idp.example.com/authorize",
            "token_endpoint": "https://idp.example.com/token",
        }
        respx.get("https://idp.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://idp.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(200, json=oidc)
        )
        result = await discovery.fetch_oauth_server_metadata("https://idp.example.com")
        assert result is not None
        assert result["authorization_endpoint"] == "https://idp.example.com/authorize"

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_both_fail(self):
        respx.get("https://nope.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://nope.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        result = await discovery.fetch_oauth_server_metadata("https://nope.example.com")
        assert result is None


class TestDiscoverViaMcpProbe:
    @pytest.mark.anyio
    @respx.mock
    async def test_full_cross_host_flow_like_supabase(self):
        """MCP host (mcp.x) probes; PRM points at a different AS host (api.x)."""
        # Step 1: probe MCP URL
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
                },
            )
        )
        # Step 2: fetch PRM
        respx.get("https://mcp.example.com/.well-known/oauth-protected-resource/mcp").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://api.example.com"],
                    "scopes_supported": ["read", "write"],
                },
            )
        )
        # Step 3: fetch AS metadata at the different host
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/oauth/authorize",
                    "token_endpoint": "https://api.example.com/oauth/token",
                    "registration_endpoint": "https://api.example.com/oauth/register",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is not None
        assert result["discovery_method"] == "mcp_probe"
        assert result["issuer"] == "https://api.example.com"
        assert result["authorization_endpoint"] == "https://api.example.com/oauth/authorize"
        assert result["registration_endpoint"] == "https://api.example.com/oauth/register"
        # PRM scopes take precedence over AS scopes
        assert result["scopes_supported"] == ["read", "write"]
        assert result["resource"] == "https://mcp.example.com/mcp"
        assert result["resource_metadata_url"] == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

    @pytest.mark.anyio
    @respx.mock
    async def test_query_string_preserved_through_probe_and_fetch(self):
        prm_url_with_query = (
            "https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc"
        )
        respx.get("https://mcp.supabase.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": f'Bearer resource_metadata="{prm_url_with_query}"'
                },
            )
        )
        # Match the EXACT URL including query string
        respx.get(prm_url_with_query).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.supabase.com/mcp?project_ref=abc",
                    "authorization_servers": ["https://api.supabase.com"],
                    "scopes_supported": ["projects:read"],
                },
            )
        )
        respx.get("https://api.supabase.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.supabase.com",
                    "authorization_endpoint": "https://api.supabase.com/v1/oauth/authorize",
                    "token_endpoint": "https://api.supabase.com/v1/oauth/token",
                    "registration_endpoint": "https://api.supabase.com/platform/oauth/apps/register",
                },
            )
        )
        respx.get("https://api.supabase.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe("https://mcp.supabase.com/mcp")
        assert result is not None
        assert result["resource_metadata_url"] == prm_url_with_query
        assert result["resource"] == "https://mcp.supabase.com/mcp?project_ref=abc"
        assert result["registration_endpoint"] == "https://api.supabase.com/platform/oauth/apps/register"

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_prm_has_no_auth_servers(self):
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/prm"'
                },
            )
        )
        respx.get("https://mcp.example.com/prm").mock(
            return_value=httpx.Response(200, json={"resource": "https://mcp.example.com/mcp"})
        )
        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is None

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_probe_yields_nothing(self):
        respx.get("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        respx.post("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is None


class TestDiscoverLegacy:
    @pytest.mark.anyio
    @respx.mock
    async def test_host_derived_when_mcp_and_oauth_share_host(self):
        """GitLab-style: MCP URL host == OAuth issuer host."""
        respx.get("https://gitlab.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://gitlab.com",
                    "authorization_endpoint": "https://gitlab.com/oauth/authorize",
                    "token_endpoint": "https://gitlab.com/oauth/token",
                    "registration_endpoint": "https://gitlab.com/oauth/applications",
                },
            )
        )
        respx.get("https://gitlab.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://gitlab.com/.well-known/oauth-protected-resource/api/v4/mcp").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_legacy("https://gitlab.com/api/v4/mcp")
        assert result is not None
        assert result["discovery_method"] == "legacy_host"
        assert result["issuer"] == "https://gitlab.com"
        assert result["registration_endpoint"] == "https://gitlab.com/oauth/applications"

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_no_metadata(self):
        respx.get("https://example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        result = await discovery.discover_legacy("https://example.com/mcp")
        assert result is None


class TestDiscover:
    @pytest.mark.anyio
    @respx.mock
    async def test_prefers_probe_when_available(self):
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": 'Bearer resource_metadata="https://mcp.example.com/prm"'
                },
            )
        )
        respx.get("https://mcp.example.com/prm").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://api.example.com"],
                },
            )
        )
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                    "registration_endpoint": "https://api.example.com/register",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover("https://mcp.example.com/mcp")
        assert result is not None
        assert result["discovery_method"] == "mcp_probe"

    @pytest.mark.anyio
    @respx.mock
    async def test_falls_back_to_legacy_when_probe_fails(self):
        # Probe returns no WWW-Authenticate
        respx.get("https://gitlab.com/api/v4/mcp").mock(return_value=httpx.Response(200))
        respx.post("https://gitlab.com/api/v4/mcp").mock(return_value=httpx.Response(200))
        # Legacy host discovery succeeds
        respx.get("https://gitlab.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://gitlab.com",
                    "authorization_endpoint": "https://gitlab.com/oauth/authorize",
                    "token_endpoint": "https://gitlab.com/oauth/token",
                    "registration_endpoint": "https://gitlab.com/oauth/applications",
                },
            )
        )
        respx.get("https://gitlab.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get("https://gitlab.com/.well-known/oauth-protected-resource/api/v4/mcp").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover("https://gitlab.com/api/v4/mcp")
        assert result is not None
        assert result["discovery_method"] == "legacy_host"
