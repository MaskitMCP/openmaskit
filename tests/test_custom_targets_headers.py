"""Tests for the custom HTTP headers field on custom-target install.

Covers openmaskit.web.routes.custom_targets._build_config and _clean_http_headers
— the entry point where the install API normalizes and rejects header configs
before persistence. End-to-end coverage of the connect_upstream wiring lives in
tests/test_upstream_http_headers.py.
"""

from __future__ import annotations

import pytest

from openmaskit.web.routes.custom_targets import _build_config, _clean_http_headers


class TestCleanHttpHeaders:
    def test_none_returns_empty(self):
        cleaned, err = _clean_http_headers(None)
        assert err is None
        assert cleaned == {}

    def test_non_dict_rejected(self):
        cleaned, err = _clean_http_headers(["DD-API-KEY", "v"])
        assert cleaned is None
        assert err is not None and "object" in err

    def test_non_string_value_rejected(self):
        cleaned, err = _clean_http_headers({"DD-API-KEY": 123})
        assert cleaned is None
        assert err is not None and "strings" in err

    def test_strips_whitespace_from_keys_and_values(self):
        cleaned, err = _clean_http_headers({"  DD-API-KEY  ": "  abc  "})
        assert err is None
        assert cleaned == {"DD-API-KEY": "abc"}

    def test_drops_rows_with_empty_name_or_value(self):
        cleaned, err = _clean_http_headers(
            {"": "v", "DD-API-KEY": "", "X-Real": "ok"}
        )
        assert err is None
        assert cleaned == {"X-Real": "ok"}

    def test_rejects_cr_lf_in_name(self):
        cleaned, err = _clean_http_headers({"Bad\r\nName": "v"})
        assert cleaned is None
        assert err is not None and "CR" in err

    def test_rejects_cr_lf_in_value(self):
        cleaned, err = _clean_http_headers({"X-Header": "val\nInjected: yes"})
        assert cleaned is None
        assert err is not None and "CR" in err

    def test_rejects_duplicate_keys_after_normalization(self):
        cleaned, err = _clean_http_headers({"X-Key": "a", "  X-Key  ": "b"})
        assert cleaned is None
        assert err is not None and "duplicate" in err


class TestReservedHeaderDenylist:
    """The cleaner rejects transport-layer, MCP-protocol, and openmaskit-
    namespace headers loudly at submit-time. The goal is "config error you
    can see and fix" instead of "upstream 401 a week later you can't trace."
    """

    @pytest.mark.parametrize(
        "name",
        ["Host", "host", "HOST", "Content-Length", "content-length",
         "Transfer-Encoding", "Connection"],
    )
    def test_rejects_transport_layer_headers(self, name):
        cleaned, err = _clean_http_headers({name: "value"})
        assert cleaned is None
        assert err is not None
        assert name in err and "reserved" in err

    @pytest.mark.parametrize("name", ["mcp-protocol-version", "MCP-Session-Id"])
    def test_rejects_mcp_protocol_headers(self, name):
        cleaned, err = _clean_http_headers({name: "value"})
        assert cleaned is None
        assert err is not None and "reserved" in err

    @pytest.mark.parametrize(
        "name",
        [
            "openmaskit-trace-id",
            "OpenMaskit-Routing",
            "OPENMASKIT-DEBUG",
            "X-OpenMaskit-Internal",  # contains, not prefix
            "Acme-Openmaskit-Compat",  # substring elsewhere in the name
            "openmaskit",  # exact match
        ],
    )
    def test_rejects_openmaskit_namespace_substring(self, name):
        cleaned, err = _clean_http_headers({name: "value"})
        assert cleaned is None
        assert err is not None and "openmaskit" in err

    def test_allows_vendor_namespaces(self):
        """Vendor-prefixed credential headers stay allowed."""
        cleaned, err = _clean_http_headers(
            {
                "DD-API-KEY": "abc",
                "Stripe-Account": "acct_123",
                "Notion-Version": "2022-06-28",
                "X-API-KEY": "k",
                "User-Agent": "OpenMaskit/0.2",
            }
        )
        assert err is None
        assert cleaned == {
            "DD-API-KEY": "abc",
            "Stripe-Account": "acct_123",
            "Notion-Version": "2022-06-28",
            "X-API-KEY": "k",
            "User-Agent": "OpenMaskit/0.2",
        }

    def test_allows_authorization_when_no_oauth(self):
        """Authorization remains allowed here — the OAuth-collision check
        lives in custom_targets._build_config / the model validator.
        """
        cleaned, err = _clean_http_headers({"Authorization": "Bearer abc"})
        assert err is None
        assert cleaned == {"Authorization": "Bearer abc"}


class TestBuildConfigHttpHeaders:
    def test_http_with_headers_round_trips(self):
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"DD-API-KEY": "abc", "DD-APPLICATION-KEY": "def"},
            }
        )
        assert err is None
        assert config["transport"] == "http"
        assert config["headers"] == {
            "DD-API-KEY": "abc",
            "DD-APPLICATION-KEY": "def",
        }

    def test_http_without_headers_omits_key(self):
        config, err = _build_config(
            {"transport": "http", "url": "https://example.com/mcp"}
        )
        assert err is None
        assert "headers" not in config

    def test_http_with_empty_headers_dict_omits_key(self):
        config, err = _build_config(
            {"transport": "http", "url": "https://example.com/mcp", "headers": {}}
        )
        assert err is None
        assert "headers" not in config

    def test_http_with_only_blank_header_rows_omits_key(self):
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"": "", "  ": "  "},
            }
        )
        assert err is None
        assert "headers" not in config

    def test_http_rejects_authorization_when_oauth_set(self):
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "oauth": {"client_id": "cid", "client_secret": "sec"},
                "headers": {"Authorization": "Bearer attacker"},
            }
        )
        assert config is None
        assert err is not None and "Authorization" in err

    def test_http_rejects_authorization_when_oauth_set_case_insensitive(self):
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "oauth": {"client_id": "cid", "client_secret": "sec"},
                "headers": {"authorization": "Bearer attacker"},
            }
        )
        assert config is None
        assert err is not None and "Authorization" in err

    def test_http_allows_authorization_without_oauth(self):
        # If a user wants to wire `Authorization` themselves on a non-OAuth
        # server (e.g. a static token issued out-of-band), that's their call.
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"Authorization": "Bearer static-token"},
            }
        )
        assert err is None
        assert config["headers"] == {"Authorization": "Bearer static-token"}

    def test_http_propagates_cleaner_error(self):
        config, err = _build_config(
            {
                "transport": "http",
                "url": "https://example.com/mcp",
                "headers": {"X-Header": "val\nInjected: yes"},
            }
        )
        assert config is None
        assert err is not None and "CR" in err

    def test_stdio_body_ignores_headers_field(self):
        # Defensive: 'headers' on a stdio body should not raise or appear in config.
        config, err = _build_config(
            {
                "transport": "stdio",
                "command": "uvx",
                "args": ["mcp-server"],
                "headers": {"DD-API-KEY": "abc"},
            }
        )
        assert err is None
        assert "headers" not in config
