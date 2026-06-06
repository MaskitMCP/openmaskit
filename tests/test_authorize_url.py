"""Tests for OAuth authorize-URL construction with PKCE."""

from __future__ import annotations

import base64
import hashlib
from urllib.parse import parse_qs, urlparse

from openmaskit.oauth.authorize_url import build_authorize_url, generate_pkce


class TestGeneratePkce:
    def test_verifier_length_is_within_rfc_7636_bounds(self):
        verifier, _ = generate_pkce()
        # RFC 7636 §4.1: 43..128 chars, URL-safe base64
        assert 43 <= len(verifier) <= 128

    def test_challenge_matches_s256_of_verifier(self):
        verifier, challenge = generate_pkce()
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        assert challenge == expected

    def test_each_call_produces_unique_verifier(self):
        v1, _ = generate_pkce()
        v2, _ = generate_pkce()
        assert v1 != v2

    def test_challenge_has_no_padding(self):
        _, challenge = generate_pkce()
        assert "=" not in challenge


class TestBuildAuthorizeUrl:
    def _parse(self, url: str) -> dict:
        parsed = urlparse(url)
        return {k: v[0] for k, v in parse_qs(parsed.query).items()}

    def test_includes_required_oauth_params(self):
        url = build_authorize_url(
            "https://auth.example.com/authorize",
            client_id="cid",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            scope="read write",
            state="abc",
            code_challenge="chal",
        )
        q = self._parse(url)
        assert q["response_type"] == "code"
        assert q["client_id"] == "cid"
        assert q["redirect_uri"] == "http://localhost:9473/oauth/callback/h"
        assert q["scope"] == "read write"
        assert q["state"] == "abc"
        assert q["code_challenge"] == "chal"
        assert q["code_challenge_method"] == "S256"

    def test_omits_scope_when_empty(self):
        url = build_authorize_url(
            "https://auth.example.com/authorize",
            client_id="cid",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            scope="",
            state="abc",
            code_challenge="chal",
        )
        assert "scope=" not in url

    def test_url_encodes_special_chars_in_redirect_uri(self):
        url = build_authorize_url(
            "https://auth.example.com/authorize",
            client_id="cid",
            redirect_uri="http://localhost:9473/oauth/callback/handle-with/slash",
            scope="",
            state="abc",
            code_challenge="chal",
        )
        # Slashes in the path get percent-encoded by urlencode.
        assert "%2F" in url or "handle-with%2Fslash" in url
        q = self._parse(url)
        # round-trip decodes back to the original
        assert q["redirect_uri"] == "http://localhost:9473/oauth/callback/handle-with/slash"

    def test_appends_query_when_endpoint_already_has_one(self):
        url = build_authorize_url(
            "https://auth.example.com/authorize?tenant=acme",
            client_id="cid",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            scope="",
            state="abc",
            code_challenge="chal",
        )
        # Pre-existing query is preserved; ours appended with &
        assert "tenant=acme" in url
        q = self._parse(url)
        assert q["tenant"] == "acme"
        assert q["state"] == "abc"
