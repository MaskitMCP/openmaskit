"""Tests for argument injections."""

import json

import pytest
import pytest_asyncio

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import ArgumentInjection, MaskingRule
from openmaskit.masking.store import MaskingStore


@pytest_asyncio.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


@pytest_asyncio.fixture
async def engine(store):
    e = MaskingEngine([], store)
    await e.load_aliases()
    return e


class TestInjectionModes:
    def test_set_always_overrides(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="read_only",
            value="true", mode="set",
        ))
        args = {"query": "SELECT 1", "read_only": False}
        result = engine.apply_injections("any_tool", args)
        assert result["read_only"] is True

    def test_set_adds_if_absent(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="timeout",
            value="30", mode="set",
        ))
        args = {"query": "SELECT 1"}
        result = engine.apply_injections("any_tool", args)
        assert result["timeout"] == 30

    def test_default_only_if_absent(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="limit",
            value="100", mode="default",
        ))
        args = {"query": "SELECT 1", "limit": 50}
        result = engine.apply_injections("any_tool", args)
        assert result["limit"] == 50

    def test_default_sets_when_missing(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="limit",
            value="100", mode="default",
        ))
        args = {"query": "SELECT 1"}
        result = engine.apply_injections("any_tool", args)
        assert result["limit"] == 100

    def test_append_to_string(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="command",
            value='" --dry-run"', mode="append",
        ))
        args = {"command": "deploy"}
        result = engine.apply_injections("any_tool", args)
        assert result["command"] == "deploy --dry-run"

    def test_append_to_list(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="flags",
            value='"--safe"', mode="append",
        ))
        args = {"flags": ["--verbose"]}
        result = engine.apply_injections("any_tool", args)
        assert result["flags"] == ["--verbose", "--safe"]

    def test_append_list_to_list(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="items",
            value='["c", "d"]', mode="append",
        ))
        args = {"items": ["a", "b"]}
        result = engine.apply_injections("any_tool", args)
        assert result["items"] == ["a", "b", "c", "d"]

    def test_append_when_absent_sets_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="extra",
            value='"hello"', mode="append",
        ))
        args = {}
        result = engine.apply_injections("any_tool", args)
        assert result["extra"] == "hello"


class TestInjectionValueTypes:
    def test_json_string_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="name",
            value='"world"', mode="set",
        ))
        result = engine.apply_injections("tool", {})
        assert result["name"] == "world"

    def test_json_number_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="count",
            value="42", mode="set",
        ))
        result = engine.apply_injections("tool", {})
        assert result["count"] == 42

    def test_json_boolean_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="flag",
            value="false", mode="set",
        ))
        result = engine.apply_injections("tool", {})
        assert result["flag"] is False

    def test_json_object_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="config",
            value='{"key": "val"}', mode="set",
        ))
        result = engine.apply_injections("tool", {})
        assert result["config"] == {"key": "val"}

    def test_json_null_value(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="optional",
            value="null", mode="set",
        ))
        result = engine.apply_injections("tool", {"optional": "something"})
        assert result["optional"] is None


class TestInjectionFiltering:
    def test_tool_specific_injection(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="db_query", argument_name="read_only",
            value="true", mode="set",
        ))
        result = engine.apply_injections("db_query", {})
        assert result["read_only"] is True

    def test_tool_specific_skips_other_tools(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="db_query", argument_name="read_only",
            value="true", mode="set",
        ))
        result = engine.apply_injections("other_tool", {})
        assert "read_only" not in result

    def test_inactive_injection_skipped(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="x",
            value="true", mode="set", active=False,
        ))
        result = engine.apply_injections("tool", {})
        assert "x" not in result


class TestInjectionCRUD:
    def test_remove_injection(self, engine):
        engine.add_injection(ArgumentInjection(
            id=1, tool_name="*", argument_name="x",
            value="true", mode="set",
        ))
        engine.remove_injection(1)
        result = engine.apply_injections("tool", {})
        assert "x" not in result

    @pytest.mark.anyio
    async def test_store_crud(self, store):
        injection = ArgumentInjection(
            tool_name="*", argument_name="limit",
            value="100", mode="default",
        )
        iid = await store.add_injection(injection, target_name="default")
        assert iid > 0

        injections = await store.get_injections(target_name="default")
        assert len(injections) == 1
        assert injections[0].argument_name == "limit"
        assert injections[0].value == "100"
        assert injections[0].mode == "default"

        updated = await store.update_injection(iid, value="200")
        assert updated
        injections = await store.get_injections(target_name="default")
        assert injections[0].value == "200"

        deleted = await store.delete_injection(iid)
        assert deleted
        injections = await store.get_injections(target_name="default")
        assert len(injections) == 0
