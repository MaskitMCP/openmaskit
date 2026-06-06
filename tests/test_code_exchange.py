"""Tests for direct OAuth authorization-code exchange."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs

import httpx
import pytest
import respx

from openmaskit.oauth.code_exchange import exchange_code


TOKEN_URL = "https://auth.example.com/token"


def _body(call_request: httpx.Request) -> dict:
    raw = call_request.content.decode("utf-8")
    return {k: v[0] for k, v in parse_qs(raw).items()}


class TestExchangeCodeBodyShape:
    @pytest.mark.anyio
    @respx.mock
    async def test_client_secret_post_includes_secret_in_body(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        await exchange_code(
            TOKEN_URL,
            code="c",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            client_id="cid",
            code_verifier="v",
            client_secret="ssh",
            auth_method="client_secret_post",
        )
        body = _body(route.calls.last.request)
        assert body["grant_type"] == "authorization_code"
        assert body["code"] == "c"
        assert body["redirect_uri"] == "http://localhost:9473/oauth/callback/h"
        assert body["client_id"] == "cid"
        assert body["code_verifier"] == "v"
        assert body["client_secret"] == "ssh"
        # No Authorization header for _post method
        assert "authorization" not in {
            k.lower() for k in route.calls.last.request.headers.keys()
        }

    @pytest.mark.anyio
    @respx.mock
    async def test_client_secret_basic_uses_authorization_header(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        await exchange_code(
            TOKEN_URL,
            code="c",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            client_id="cid",
            code_verifier="v",
            client_secret="ssh",
            auth_method="client_secret_basic",
        )
        body = _body(route.calls.last.request)
        assert "client_secret" not in body
        expected = "Basic " + base64.b64encode(b"cid:ssh").decode("ascii")
        assert route.calls.last.request.headers["Authorization"] == expected

    @pytest.mark.anyio
    @respx.mock
    async def test_none_omits_secret(self):
        route = respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(200, json={"access_token": "tok"})
        )
        await exchange_code(
            TOKEN_URL,
            code="c",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            client_id="cid",
            code_verifier="v",
            auth_method="none",
        )
        body = _body(route.calls.last.request)
        assert "client_secret" not in body
        assert "authorization" not in {
            k.lower() for k in route.calls.last.request.headers.keys()
        }

    @pytest.mark.anyio
    async def test_basic_requires_secret(self):
        with pytest.raises(RuntimeError, match="client_secret_basic"):
            await exchange_code(
                TOKEN_URL,
                code="c",
                redirect_uri="http://localhost:9473/oauth/callback/h",
                client_id="cid",
                code_verifier="v",
                client_secret=None,
                auth_method="client_secret_basic",
            )


class TestExchangeCodeErrorSurfacing:
    @pytest.mark.anyio
    @respx.mock
    async def test_surfaces_rfc_6749_error_description(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={
                    "error": "invalid_grant",
                    "error_description": "Code already used",
                },
            )
        )
        with pytest.raises(RuntimeError, match="invalid_grant.*Code already used"):
            await exchange_code(
                TOKEN_URL,
                code="c",
                redirect_uri="http://localhost:9473/oauth/callback/h",
                client_id="cid",
                code_verifier="v",
                client_secret="ssh",
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_falls_back_to_body_snippet_when_not_json(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(500, text="upstream auth backend down")
        )
        with pytest.raises(RuntimeError, match="upstream auth backend down"):
            await exchange_code(
                TOKEN_URL,
                code="c",
                redirect_uri="http://localhost:9473/oauth/callback/h",
                client_id="cid",
                code_verifier="v",
                client_secret="ssh",
            )

    @pytest.mark.anyio
    @respx.mock
    async def test_returns_token_payload_on_success(self):
        respx.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "tok",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "ref",
                    "scope": "read",
                },
            )
        )
        result = await exchange_code(
            TOKEN_URL,
            code="c",
            redirect_uri="http://localhost:9473/oauth/callback/h",
            client_id="cid",
            code_verifier="v",
            client_secret="ssh",
        )
        assert result["access_token"] == "tok"
        assert result["refresh_token"] == "ref"
        assert result["expires_in"] == 3600
