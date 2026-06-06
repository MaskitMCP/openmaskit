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


class TestExtractScopeFromWwwAuthenticate:
    def test_quoted_multi_token(self):
        header = 'Bearer scope="read write admin"'
        assert discovery.extract_scope_from_www_authenticate(header) == [
            "read",
            "write",
            "admin",
        ]

    def test_quoted_single_token(self):
        header = 'Bearer scope="admin"'
        assert discovery.extract_scope_from_www_authenticate(header) == ["admin"]

    def test_unquoted_single_token(self):
        # RFC 6749 §3.3 token grammar permits unquoted single tokens — no
        # whitespace allowed in the value, so unquoted forms are rare but legal.
        header = "Bearer scope=read"
        assert discovery.extract_scope_from_www_authenticate(header) == ["read"]

    def test_scope_before_other_params(self):
        header = 'Bearer scope="a b", error="invalid_token"'
        assert discovery.extract_scope_from_www_authenticate(header) == ["a", "b"]

    def test_scope_after_other_params(self):
        header = 'Bearer error="invalid_token", resource_metadata="https://x/prm", scope="a b"'
        assert discovery.extract_scope_from_www_authenticate(header) == ["a", "b"]

    def test_param_name_is_case_insensitive(self):
        # RFC 7235 §2.1: auth-param name is case-insensitive.
        assert discovery.extract_scope_from_www_authenticate(
            'Bearer Scope="read"'
        ) == ["read"]
        assert discovery.extract_scope_from_www_authenticate(
            'Bearer SCOPE="read"'
        ) == ["read"]

    def test_value_case_preserved(self):
        # RFC 6749 §3.3: scope values are case-sensitive — must not lowercase.
        header = 'Bearer scope="Read Write"'
        assert discovery.extract_scope_from_www_authenticate(header) == [
            "Read",
            "Write",
        ]

    def test_multiple_spaces_between_tokens(self):
        # Defensive: strictly RFC 6749 says single SP, but real servers
        # sometimes emit multiple. `.split()` handles both transparently.
        header = 'Bearer scope="read   write"'
        assert discovery.extract_scope_from_www_authenticate(header) == [
            "read",
            "write",
        ]

    def test_empty_quoted_value(self):
        # `scope=""` is present-but-empty; distinct from absent.
        assert discovery.extract_scope_from_www_authenticate('Bearer scope=""') == []

    def test_returns_none_when_absent(self):
        assert (
            discovery.extract_scope_from_www_authenticate(
                'Bearer realm="x", resource_metadata="https://x/prm"'
            )
            is None
        )

    def test_returns_none_for_empty_header(self):
        assert discovery.extract_scope_from_www_authenticate("") is None
        assert discovery.extract_scope_from_www_authenticate(None) is None  # type: ignore[arg-type]


class TestProbeMcpForWwwAuthenticate:
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
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.example.com/mcp"
        )
        assert url == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        assert scopes is None

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
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.supabase.com/mcp"
        )
        assert url == "https://mcp.supabase.com/.well-known/oauth-protected-resource/mcp?project_ref=abc"
        assert scopes is None

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
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.example.com/mcp"
        )
        assert url == "https://mcp.example.com/prm"
        assert scopes is None

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_when_no_www_authenticate(self):
        respx.get("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        respx.post("https://mcp.example.com/mcp").mock(return_value=httpx.Response(200))
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.example.com/mcp"
        )
        assert url is None
        assert scopes is None

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_none_on_network_error(self):
        respx.get("https://nope.example.com/mcp").mock(side_effect=httpx.ConnectError("boom"))
        respx.post("https://nope.example.com/mcp").mock(side_effect=httpx.ConnectError("boom"))
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://nope.example.com/mcp"
        )
        assert url is None
        assert scopes is None

    @pytest.mark.anyio
    @respx.mock
    async def test_extracts_both_prm_url_and_scope_from_same_challenge(self):
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.example.com/prm", '
                        'scope="read write"'
                    )
                },
            )
        )
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.example.com/mcp"
        )
        assert url == "https://mcp.example.com/prm"
        assert scopes == ["read", "write"]

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_scope_only_when_prm_absent(self):
        """Server emits `scope` but no `resource_metadata` — still useful."""
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer scope="read"'},
            )
        )
        url, scopes = await discovery.probe_mcp_for_www_authenticate(
            "https://mcp.example.com/mcp"
        )
        assert url is None
        assert scopes == ["read"]


class TestIssuerMatches:
    def test_exact_match(self):
        assert discovery.issuer_matches(
            "https://access.stripe.com/mcp", "https://access.stripe.com/mcp"
        )

    def test_trailing_slash_normalised(self):
        assert discovery.issuer_matches(
            "https://access.stripe.com/mcp/", "https://access.stripe.com/mcp"
        )
        assert discovery.issuer_matches(
            "https://access.stripe.com/mcp", "https://access.stripe.com/mcp/"
        )

    def test_mismatch_rejected(self):
        assert not discovery.issuer_matches(
            "https://access.stripe.com/mcp", "https://evil.example.com/mcp"
        )

    def test_path_difference_rejected(self):
        assert not discovery.issuer_matches(
            "https://access.stripe.com/mcp", "https://access.stripe.com/other"
        )

    def test_missing_claimed_issuer_passes(self):
        # AS without issuer field — RFC 8414 §3.3 has nothing to compare;
        # we don't reject on absence alone.
        assert discovery.issuer_matches("https://access.stripe.com/mcp", None)
        assert discovery.issuer_matches("https://access.stripe.com/mcp", "")


class TestWellknownMetadataUrls:
    def test_root_issuer_returns_single_url(self):
        urls = discovery.wellknown_metadata_urls(
            "https://auth.example.com", "oauth-authorization-server"
        )
        assert urls == [
            "https://auth.example.com/.well-known/oauth-authorization-server"
        ]

    def test_root_issuer_with_trailing_slash(self):
        urls = discovery.wellknown_metadata_urls(
            "https://auth.example.com/", "oauth-authorization-server"
        )
        assert urls == [
            "https://auth.example.com/.well-known/oauth-authorization-server"
        ]

    def test_path_issuer_prefers_rfc8414_path_insertion(self):
        urls = discovery.wellknown_metadata_urls(
            "https://access.stripe.com/mcp", "oauth-authorization-server"
        )
        assert urls == [
            "https://access.stripe.com/.well-known/oauth-authorization-server/mcp",
            "https://access.stripe.com/mcp/.well-known/oauth-authorization-server",
        ]

    def test_path_issuer_openid_configuration(self):
        urls = discovery.wellknown_metadata_urls(
            "https://idp.example.com/tenant1", "openid-configuration"
        )
        assert urls == [
            "https://idp.example.com/.well-known/openid-configuration/tenant1",
            "https://idp.example.com/tenant1/.well-known/openid-configuration",
        ]

    def test_multi_segment_path(self):
        urls = discovery.wellknown_metadata_urls(
            "https://example.com/a/b/c", "oauth-authorization-server"
        )
        assert urls[0] == (
            "https://example.com/.well-known/oauth-authorization-server/a/b/c"
        )


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

    @pytest.mark.anyio
    @respx.mock
    async def test_path_issuer_uses_rfc8414_path_insertion(self):
        """Stripe-shape: issuer has path; AS metadata lives at /.well-known/.../mcp."""
        meta = {
            "issuer": "https://access.stripe.com/mcp",
            "authorization_endpoint": "https://access.stripe.com/mcp/oauth2/authorize",
            "token_endpoint": "https://access.stripe.com/mcp/oauth2/token",
            "registration_endpoint": "https://access.stripe.com/mcp/oauth2/register",
        }
        respx.get(
            "https://access.stripe.com/.well-known/oauth-authorization-server/mcp"
        ).mock(return_value=httpx.Response(200, json=meta))
        respx.get(
            "https://access.stripe.com/.well-known/openid-configuration/mcp"
        ).mock(return_value=httpx.Response(404))
        result = await discovery.fetch_oauth_server_metadata(
            "https://access.stripe.com/mcp"
        )
        assert result is not None
        assert result["registration_endpoint"] == (
            "https://access.stripe.com/mcp/oauth2/register"
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_accepts_metadata_with_mismatched_issuer(self):
        """Slack: PRM points at mcp.slack.com but AS metadata declares
        issuer slack.com. RFC 8414 §3.3 says these MUST match; real-world
        deployments routinely don't. The MCP SDK doesn't enforce the check
        and neither do we — the URL we fetched from is the authoritative
        source for where the AS lives.
        """
        mismatched = {
            "issuer": "https://impostor.example.com",
            "authorization_endpoint": "https://impostor.example.com/authorize",
            "token_endpoint": "https://impostor.example.com/token",
        }
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(200, json=mismatched)
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        result = await discovery.fetch_oauth_server_metadata("https://api.example.com")
        assert result is not None
        assert result["authorization_endpoint"] == (
            "https://impostor.example.com/authorize"
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_spec_form_wins_even_when_issuer_disagrees(self):
        """Spec-form returns first; we no longer skip on issuer mismatch,
        so the append-form is never consulted in this case.
        """
        spec_form = {
            "issuer": "https://impostor.example.com/tenant1",
            "authorization_endpoint": "https://legacy.example.com/tenant1/authorize",
            "token_endpoint": "https://legacy.example.com/tenant1/token",
            "registration_endpoint": "https://legacy.example.com/tenant1/spec-form-register",
        }
        respx.get(
            "https://legacy.example.com/.well-known/oauth-authorization-server/tenant1"
        ).mock(return_value=httpx.Response(200, json=spec_form))
        respx.get(
            "https://legacy.example.com/.well-known/openid-configuration/tenant1"
        ).mock(return_value=httpx.Response(404))
        result = await discovery.fetch_oauth_server_metadata(
            "https://legacy.example.com/tenant1"
        )
        assert result is not None
        assert result["registration_endpoint"] == (
            "https://legacy.example.com/tenant1/spec-form-register"
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_accepts_metadata_without_issuer_field(self):
        """AS that omits issuer entirely — we don't reject on absence."""
        meta = {
            "authorization_endpoint": "https://api.example.com/authorize",
            "token_endpoint": "https://api.example.com/token",
            "registration_endpoint": "https://api.example.com/register",
        }
        respx.get(
            "https://api.example.com/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json=meta))
        respx.get(
            "https://api.example.com/.well-known/openid-configuration"
        ).mock(return_value=httpx.Response(404))
        result = await discovery.fetch_oauth_server_metadata("https://api.example.com")
        assert result is not None
        assert result["registration_endpoint"] == "https://api.example.com/register"

    @pytest.mark.anyio
    @respx.mock
    async def test_path_issuer_falls_back_to_appended_form(self):
        """Non-spec-compliant server serves only the appended form — still works."""
        meta = {
            "issuer": "https://legacy.example.com/tenant1",
            "authorization_endpoint": "https://legacy.example.com/tenant1/oauth/authorize",
            "token_endpoint": "https://legacy.example.com/tenant1/oauth/token",
            "registration_endpoint": "https://legacy.example.com/tenant1/oauth/register",
        }
        respx.get(
            "https://legacy.example.com/.well-known/oauth-authorization-server/tenant1"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://legacy.example.com/tenant1/.well-known/oauth-authorization-server"
        ).mock(return_value=httpx.Response(200, json=meta))
        respx.get(
            "https://legacy.example.com/.well-known/openid-configuration/tenant1"
        ).mock(return_value=httpx.Response(404))
        respx.get(
            "https://legacy.example.com/tenant1/.well-known/openid-configuration"
        ).mock(return_value=httpx.Response(404))
        result = await discovery.fetch_oauth_server_metadata(
            "https://legacy.example.com/tenant1"
        )
        assert result is not None
        assert result["registration_endpoint"] == (
            "https://legacy.example.com/tenant1/oauth/register"
        )


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
        # PRM scopes drive the menu; no WWW-Auth scope so nothing is required.
        assert result["scopes"] == [
            {"scope": "read", "required": False},
            {"scope": "write", "required": False},
        ]
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

    @pytest.mark.anyio
    @respx.mock
    async def test_www_authenticate_scope_used_when_prm_omits_scopes(self):
        """When PRM has no `scopes_supported`, WWW-Auth `scope` populates the
        menu — and every entry is `required: True` because the canonical
        required signal is the same source we fell back to."""
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.example.com/prm", '
                        'scope="repo:read repo:write"'
                    )
                },
            )
        )
        respx.get("https://mcp.example.com/prm").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://api.example.com"],
                    # No `scopes_supported` — this is the gap WWW-Auth fills.
                },
            )
        )
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is not None
        assert result["scopes"] == [
            {"scope": "repo:read", "required": True},
            {"scope": "repo:write", "required": True},
        ]

    @pytest.mark.anyio
    @respx.mock
    async def test_supported_and_required_combined_when_both_signal(self):
        """PRM drives the menu; WWW-Auth tags the `required` flag per entry.

        PRM is the catalog (every entry appears); WWW-Auth is the locked
        subset (those entries get `required: True`). The install picker
        renders the menu and pre-checks + locks the required ones.
        """
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.example.com/prm", '
                        'scope="read"'
                    )
                },
            )
        )
        respx.get("https://mcp.example.com/prm").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://api.example.com"],
                    "scopes_supported": ["read", "write", "admin"],
                },
            )
        )
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is not None
        assert result["scopes"] == [
            {"scope": "read", "required": True},
            {"scope": "write", "required": False},
            {"scope": "admin", "required": False},
        ]

    @pytest.mark.anyio
    @respx.mock
    async def test_required_not_in_supported_is_appended_with_required_flag(self):
        """Required ⊄ supported is malformed-but-legal; the straggler is
        appended at the end of the unified list with `required: True`."""
        respx.get("https://mcp.example.com/mcp").mock(
            return_value=httpx.Response(
                401,
                headers={
                    "WWW-Authenticate": (
                        'Bearer resource_metadata="https://mcp.example.com/prm", '
                        'scope="ghost_scope"'
                    )
                },
            )
        )
        respx.get("https://mcp.example.com/prm").mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://mcp.example.com/mcp",
                    "authorization_servers": ["https://api.example.com"],
                    "scopes_supported": ["read", "write"],
                },
            )
        )
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe(
            "https://mcp.example.com/mcp"
        )

        assert result is not None
        # PRM scopes come first in order, then the malformed required token
        # appended at the end with `required: True`.
        assert result["scopes"] == [
            {"scope": "read", "required": False},
            {"scope": "write", "required": False},
            {"scope": "ghost_scope", "required": True},
        ]

    @pytest.mark.anyio
    @respx.mock
    async def test_prm_scopes_used_when_www_authenticate_omits_scope(self):
        """No `scope` in the challenge → PRM `scopes_supported` is the menu;
        every entry is `required: False` because the server didn't enforce any."""
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
                    "scopes_supported": ["from_prm"],
                },
            )
        )
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                    "scopes_supported": ["from_as"],
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_via_mcp_probe("https://mcp.example.com/mcp")
        assert result is not None
        assert result["scopes"] == [{"scope": "from_prm", "required": False}]


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
        respx.get("https://gitlab.com/.well-known/oauth-protected-resource").mock(
            return_value=httpx.Response(404)
        )

        result = await discovery.discover_legacy("https://gitlab.com/api/v4/mcp")
        assert result is not None
        assert result["discovery_method"] == "legacy_host"
        assert result["issuer"] == "https://gitlab.com"
        assert result["registration_endpoint"] == "https://gitlab.com/oauth/applications"
        assert result["resource_metadata_url"] is None
        # Legacy flow never probes WWW-Authenticate, so nothing is required.
        assert all(not s["required"] for s in result["scopes"])

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

    @pytest.mark.anyio
    @respx.mock
    async def test_falls_back_to_root_prm_when_path_prm_missing(self):
        """Compliant PRM server with no path-form PRM still gets discovered."""
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                    "registration_endpoint": "https://api.example.com/register",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        # Path-form PRM not served by this AS.
        respx.get(
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp"
        ).mock(return_value=httpx.Response(404))
        # Root-form PRM IS served — this is the new fallback path.
        respx.get(
            "https://api.example.com/.well-known/oauth-protected-resource"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://api.example.com",
                    "scopes_supported": ["scope_a", "scope_b"],
                },
            )
        )
        result = await discovery.discover_legacy("https://api.example.com/v1/mcp")
        assert result is not None
        assert result["discovery_method"] == "legacy_host+resource"
        assert result["scopes"] == [
            {"scope": "scope_a", "required": False},
            {"scope": "scope_b", "required": False},
        ]
        assert result["resource_metadata_url"] == (
            "https://api.example.com/.well-known/oauth-protected-resource"
        )

    @pytest.mark.anyio
    @respx.mock
    async def test_root_prm_used_for_path_less_mcp_url(self):
        """An MCP URL with no path now still tries the root PRM (previously skipped)."""
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get(
            "https://api.example.com/.well-known/oauth-protected-resource"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://api.example.com",
                    "scopes_supported": ["read"],
                },
            )
        )
        result = await discovery.discover_legacy("https://api.example.com")
        assert result is not None
        assert result["discovery_method"] == "legacy_host+resource"
        assert result["scopes"] == [{"scope": "read", "required": False}]

    @pytest.mark.anyio
    @respx.mock
    async def test_path_prm_preferred_over_root_when_both_exist(self):
        """When both PRM locations exist, the more-specific path-form wins."""
        respx.get("https://api.example.com/.well-known/oauth-authorization-server").mock(
            return_value=httpx.Response(
                200,
                json={
                    "issuer": "https://api.example.com",
                    "authorization_endpoint": "https://api.example.com/authorize",
                    "token_endpoint": "https://api.example.com/token",
                },
            )
        )
        respx.get("https://api.example.com/.well-known/openid-configuration").mock(
            return_value=httpx.Response(404)
        )
        respx.get(
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://api.example.com/v1/mcp",
                    "scopes_supported": ["path_specific"],
                },
            )
        )
        # Root also exists but the path-form should be preferred.
        respx.get(
            "https://api.example.com/.well-known/oauth-protected-resource"
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "resource": "https://api.example.com",
                    "scopes_supported": ["generic"],
                },
            )
        )
        result = await discovery.discover_legacy("https://api.example.com/v1/mcp")
        assert result is not None
        assert result["scopes"] == [{"scope": "path_specific", "required": False}]
        assert result["resource_metadata_url"] == (
            "https://api.example.com/.well-known/oauth-protected-resource/v1/mcp"
        )


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
