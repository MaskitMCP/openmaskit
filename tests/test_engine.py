"""Tests for the masking engine."""

import pytest
import pytest_asyncio

from maskit.masking.engine import MaskingEngine
from maskit.masking.rules import MaskingRule, get_nested_value, set_nested_value
from maskit.masking.store import MaskingStore


@pytest.fixture
def rules():
    return [
        MaskingRule(tool_name="get_connection", field_path="host", alias_prefix="host"),
        MaskingRule(tool_name="get_connection", field_path="connection.password", alias_prefix="secret"),
        MaskingRule(tool_name="*", field_path="api_key", alias_prefix="api_key"),
    ]


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def engine(rules, store):
    e = MaskingEngine(rules, store)
    await e.load_aliases()
    return e


class TestNestedPaths:
    def test_get_nested_value_simple(self):
        data = {"host": "mydb.com"}
        assert get_nested_value(data, "host") == "mydb.com"

    def test_get_nested_value_deep(self):
        data = {"connection": {"password": "secret123", "port": 5432}}
        assert get_nested_value(data, "connection.password") == "secret123"

    def test_get_nested_value_missing(self):
        data = {"foo": "bar"}
        assert get_nested_value(data, "missing.path") is None

    def test_set_nested_value_simple(self):
        data = {"host": "mydb.com"}
        assert set_nested_value(data, "host", "masked_1")
        assert data["host"] == "masked_1"

    def test_set_nested_value_deep(self):
        data = {"connection": {"password": "secret123", "port": 5432}}
        assert set_nested_value(data, "connection.password", "masked_pw_1")
        assert data["connection"]["password"] == "masked_pw_1"
        assert data["connection"]["port"] == 5432

    def test_set_nested_value_missing_returns_false(self):
        data = {"foo": "bar"}
        assert not set_nested_value(data, "missing.path", "x")


class TestMaskingEngine:
    @pytest.mark.anyio
    async def test_mask_structured_content(self, engine):
        result = {
            "structuredContent": {
                "host": "production-db.internal.com",
                "port": 5432,
            }
        }
        masked = engine.mask_response("get_connection", result)
        assert masked["structuredContent"]["host"] == "host_1"
        assert masked["structuredContent"]["port"] == 5432

    @pytest.mark.anyio
    async def test_mask_nested_field(self, engine):
        result = {
            "structuredContent": {
                "connection": {"password": "super_secret", "host": "localhost"},
            }
        }
        masked = engine.mask_response("get_connection", result)
        assert masked["structuredContent"]["connection"]["password"] == "secret_1"

    @pytest.mark.anyio
    async def test_mask_text_content_json(self, engine):
        import json

        result = {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"host": "prod.example.com", "port": 3306}),
                }
            ]
        }
        masked = engine.mask_response("get_connection", result)
        parsed = json.loads(masked["content"][0]["text"])
        assert parsed["host"] == "host_1"
        assert parsed["port"] == 3306

    @pytest.mark.anyio
    async def test_wildcard_rule(self, engine):
        result = {
            "structuredContent": {"api_key": "sk-abc123", "name": "test"}
        }
        masked = engine.mask_response("any_tool", result)
        assert masked["structuredContent"]["api_key"] == "api_key_1"
        assert masked["structuredContent"]["name"] == "test"

    @pytest.mark.anyio
    async def test_unmask_arguments(self, engine):
        # First mask something
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "real-host.com"}
        })

        # Now unmask
        args = {"target_host": "host_1", "port": 5432}
        unmasked = engine.unmask_arguments("get_connection", args)
        assert unmasked["target_host"] == "real-host.com"
        assert unmasked["port"] == 5432

    @pytest.mark.anyio
    async def test_same_value_gets_same_alias(self, engine):
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "same-host.com"}
        })
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "same-host.com"}
        })
        # Should still be host_1, not host_2
        assert engine._alias_cache.get("host_1") == "same-host.com"
        assert "host_2" not in engine._alias_cache

    @pytest.mark.anyio
    async def test_different_values_get_different_aliases(self, engine):
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "host-a.com"}
        })
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "host-b.com"}
        })
        assert engine._alias_cache["host_1"] == "host-a.com"
        assert engine._alias_cache["host_2"] == "host-b.com"

    @pytest.mark.anyio
    async def test_flush_persists_to_store(self, engine, store):
        engine.mask_response("get_connection", {
            "structuredContent": {"host": "persist-me.com"}
        })
        await engine.flush_pending()
        all_mappings = await store.get_all_mappings()
        assert any(m["real_value"] == "persist-me.com" for m in all_mappings)

    @pytest.mark.anyio
    async def test_no_rules_match_passes_through(self, engine):
        result = {"structuredContent": {"unrelated_field": "value"}}
        masked = engine.mask_response("unknown_tool", result)
        # Only wildcard rule for api_key applies, but field isn't api_key
        assert masked["structuredContent"]["unrelated_field"] == "value"
