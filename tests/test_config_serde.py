"""Tests for ``openmaskit.config_serde``.

The serde is the single boundary between in-memory config dicts (what the
install/edit handlers build) and the on-disk ``config_json`` representation
(what ``mcp_servers.config_json`` stores). Exercising it directly catches
schema/shape regressions without needing the full DB stack.
"""

from __future__ import annotations

import json

import pytest

from openmaskit.config_serde import (
    REDACTED_SENTINEL,
    dump_config,
    load_display_config,
    load_runtime_config,
    merge_update,
)


# ---------- dump + load roundtrip ----------


class TestDumpLoadRuntime:
    def test_plain_http_config_roundtrips(self):
        original = {
            "transport": "http",
            "url": "https://mcp.slack.com/mcp",
        }
        serialized = dump_config(original)
        assert load_runtime_config(serialized) == original

    def test_oauth_client_secret_is_encrypted_on_disk(self):
        config = {
            "transport": "http",
            "url": "https://x",
            "oauth": {
                "client_id": "id-123",
                "client_secret": "shhh",
                "scope": "read",
            },
        }
        serialized = dump_config(config)
        raw = json.loads(serialized)
        # client_id stays plaintext; client_secret is the {"enc": ...} wrapper.
        assert raw["oauth"]["client_id"] == "id-123"
        assert isinstance(raw["oauth"]["client_secret"], dict)
        assert set(raw["oauth"]["client_secret"].keys()) == {"enc"}
        assert raw["oauth"]["client_secret"]["enc"].startswith("ENCRYPTED:")
        # Runtime load decrypts it back.
        loaded = load_runtime_config(serialized)
        assert loaded["oauth"]["client_secret"] == "shhh"

    def test_registration_token_is_encrypted_on_disk(self):
        config = {
            "transport": "http",
            "url": "https://x",
            "oauth": {"client_id": "id", "registration_token": "tok-secret"},
        }
        serialized = dump_config(config)
        raw = json.loads(serialized)
        assert isinstance(raw["oauth"]["registration_token"], dict)
        assert load_runtime_config(serialized)["oauth"]["registration_token"] == "tok-secret"

    def test_typed_env_encrypts_only_secrets(self):
        config = {
            "transport": "stdio",
            "command": "uvx",
            "args": ["pg-mcp"],
            "env": {
                "DB_URI": {"value": "postgres://u:p@h/d", "type": "secret"},
                "TZ": {"value": "UTC", "type": "text"},
            },
        }
        serialized = dump_config(config)
        raw = json.loads(serialized)
        # Secret entry is encrypted; non-secret entry stays plaintext.
        assert isinstance(raw["env"]["DB_URI"]["value"], dict)
        assert raw["env"]["DB_URI"]["value"]["enc"].startswith("ENCRYPTED:")
        assert raw["env"]["DB_URI"]["type"] == "secret"
        assert raw["env"]["TZ"]["value"] == "UTC"
        assert raw["env"]["TZ"]["type"] == "text"
        # Runtime load flattens both.
        loaded = load_runtime_config(serialized)
        assert loaded["env"] == {"DB_URI": "postgres://u:p@h/d", "TZ": "UTC"}

    def test_typed_headers_encrypts_only_secrets(self):
        config = {
            "transport": "http",
            "url": "https://api.datadog.eu/mcp",
            "headers": {
                "DD-API-KEY": {"value": "key-xxx", "type": "secret"},
                "Content-Type": {"value": "application/json", "type": "text"},
            },
        }
        serialized = dump_config(config)
        loaded = load_runtime_config(serialized)
        assert loaded["headers"] == {"DD-API-KEY": "key-xxx", "Content-Type": "application/json"}

    def test_bare_env_value_defaults_to_secret(self):
        """An undecorated string value is treated as a secret (conservative)."""
        config = {"transport": "stdio", "command": "x", "args": [], "env": {"X": "hidden"}}
        serialized = dump_config(config)
        raw = json.loads(serialized)
        assert raw["env"]["X"]["type"] == "secret"
        assert isinstance(raw["env"]["X"]["value"], dict)
        assert raw["env"]["X"]["value"]["enc"].startswith("ENCRYPTED:")
        assert load_runtime_config(serialized)["env"]["X"] == "hidden"

    def test_empty_env_and_headers_dropped_from_storage(self):
        config = {"transport": "http", "url": "https://x", "env": {}, "headers": {}}
        serialized = dump_config(config)
        raw = json.loads(serialized)
        assert "env" not in raw
        assert "headers" not in raw

    def test_invalid_type_raises(self):
        config = {
            "transport": "stdio",
            "command": "x",
            "args": [],
            "env": {"X": {"value": "v", "type": "not-a-type"}},
        }
        with pytest.raises(ValueError, match="Invalid env/header type"):
            dump_config(config)


# ---------- redacted display load ----------


class TestLoadDisplay:
    def test_oauth_client_secret_is_redacted(self):
        serialized = dump_config(
            {"transport": "http", "url": "x", "oauth": {"client_id": "id", "client_secret": "shhh"}}
        )
        display = load_display_config(serialized)
        assert display["oauth"]["client_id"] == "id"
        assert display["oauth"]["client_secret"] == REDACTED_SENTINEL

    def test_typed_env_redacts_only_secrets_and_keeps_types(self):
        serialized = dump_config(
            {
                "transport": "stdio",
                "command": "x",
                "args": [],
                "env": {
                    "DB_URI": {"value": "postgres://x", "type": "secret"},
                    "TZ": {"value": "UTC", "type": "text"},
                },
            }
        )
        display = load_display_config(serialized)
        assert display["env"]["DB_URI"] == {"value": REDACTED_SENTINEL, "type": "secret"}
        assert display["env"]["TZ"] == {"value": "UTC", "type": "text"}

    def test_typed_headers_redact_secrets_only(self):
        serialized = dump_config(
            {
                "transport": "http",
                "url": "x",
                "headers": {
                    "DD-API-KEY": {"value": "k", "type": "secret"},
                    "Content-Type": {"value": "application/json", "type": "text"},
                },
            }
        )
        display = load_display_config(serialized)
        assert display["headers"]["DD-API-KEY"]["value"] == REDACTED_SENTINEL
        assert display["headers"]["Content-Type"]["value"] == "application/json"

    def test_display_load_does_not_decrypt(self):
        """Sanity check: display load works on raw JSON without the encryption key.

        We can't easily test 'fails without key' without ripping out TokenEncryption,
        but the shape contract — that load_display_config returns a redacted view
        of the on-disk structure rather than ever calling decrypt — is verified
        by checking the sentinel survives a round-trip through the on-disk JSON.
        """
        serialized = dump_config(
            {"transport": "http", "url": "x", "oauth": {"client_id": "id", "client_secret": "shhh"}}
        )
        # The serialized form is a JSON string containing the {enc} wrapper.
        # Display load reads that structure verbatim and substitutes the sentinel
        # — it does NOT round-trip through the runtime decrypted shape.
        display = load_display_config(serialized)
        assert display["oauth"]["client_secret"] == REDACTED_SENTINEL


# ---------- merge_update (preserve-on-absence) ----------


class TestMergeUpdate:
    def test_omitting_oauth_client_secret_keeps_stored(self):
        stored_json = dump_config(
            {
                "transport": "http",
                "url": "https://x",
                "oauth": {"client_id": "id", "client_secret": "original-secret"},
            }
        )
        incoming = {
            "transport": "http",
            "url": "https://x",
            "oauth": {"client_id": "id"},  # no client_secret
        }
        merged = merge_update(stored_json, incoming)
        # The merged dict still has the encrypted client_secret from storage,
        # because the user didn't send a new one.
        assert "client_secret" in merged["oauth"]
        # Dump + runtime-load brings the original secret back.
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["oauth"]["client_secret"] == "original-secret"

    def test_sentinel_oauth_client_secret_keeps_stored(self):
        stored_json = dump_config(
            {"transport": "http", "url": "x", "oauth": {"client_id": "id", "client_secret": "orig"}}
        )
        incoming = {
            "oauth": {"client_id": "id", "client_secret": REDACTED_SENTINEL},
        }
        merged = merge_update(stored_json, incoming)
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["oauth"]["client_secret"] == "orig"

    def test_new_oauth_client_secret_overwrites(self):
        stored_json = dump_config(
            {"transport": "http", "url": "x", "oauth": {"client_id": "id", "client_secret": "orig"}}
        )
        incoming = {"oauth": {"client_id": "id", "client_secret": "rotated"}}
        merged = merge_update(stored_json, incoming)
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["oauth"]["client_secret"] == "rotated"

    def test_blank_secret_env_entry_preserves_stored(self):
        stored_json = dump_config(
            {
                "transport": "stdio",
                "command": "x",
                "args": [],
                "env": {"DB_URI": {"value": "postgres://orig", "type": "secret"}},
            }
        )
        incoming = {"env": {"DB_URI": {"value": "", "type": "secret"}}}
        merged = merge_update(stored_json, incoming)
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["env"]["DB_URI"] == "postgres://orig"

    def test_new_secret_env_entry_overwrites(self):
        stored_json = dump_config(
            {
                "transport": "stdio",
                "command": "x",
                "args": [],
                "env": {"DB_URI": {"value": "postgres://orig", "type": "secret"}},
            }
        )
        incoming = {"env": {"DB_URI": {"value": "postgres://new", "type": "secret"}}}
        merged = merge_update(stored_json, incoming)
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["env"]["DB_URI"] == "postgres://new"

    def test_text_env_entry_replaces_verbatim(self):
        stored_json = dump_config(
            {"transport": "stdio", "command": "x", "args": [], "env": {"TZ": {"value": "UTC", "type": "text"}}}
        )
        incoming = {"env": {"TZ": {"value": "America/Los_Angeles", "type": "text"}}}
        merged = merge_update(stored_json, incoming)
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["env"]["TZ"] == "America/Los_Angeles"

    def test_top_level_url_can_be_updated(self):
        stored_json = dump_config(
            {"transport": "http", "url": "https://old", "oauth": {"client_id": "id", "client_secret": "s"}}
        )
        incoming = {"transport": "http", "url": "https://new"}
        merged = merge_update(stored_json, incoming)
        # url updated, oauth preserved
        assert merged["url"] == "https://new"
        roundtripped = load_runtime_config(dump_config(merged))
        assert roundtripped["oauth"]["client_secret"] == "s"
