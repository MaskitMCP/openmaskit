"""Tests for argument guardrails."""

import pytest
import pytest_asyncio

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.rules import ArgumentGuardrail, MaskingRule
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


class TestGuardrailMatching:
    def test_contains_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="query",
            match_type="contains", pattern="DROP TABLE",
            message="DROP TABLE not allowed",
        ))
        result = engine.check_guardrails("run_sql", {"query": "DROP TABLE users"})
        assert result == "DROP TABLE not allowed"

    def test_contains_no_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="query",
            match_type="contains", pattern="DROP TABLE",
            message="DROP TABLE not allowed",
        ))
        result = engine.check_guardrails("run_sql", {"query": "SELECT * FROM users"})
        assert result is None

    def test_equals_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="path",
            match_type="equals", pattern="/etc/passwd",
            message="Access denied",
        ))
        result = engine.check_guardrails("read_file", {"path": "/etc/passwd"})
        assert result == "Access denied"

    def test_equals_partial_no_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="path",
            match_type="equals", pattern="/etc/passwd",
            message="Access denied",
        ))
        result = engine.check_guardrails("read_file", {"path": "/etc/passwd.bak"})
        assert result is None

    def test_regex_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="query",
            match_type="regex", pattern=r"(?i)\b(DROP|DELETE|TRUNCATE)\b",
            message="Destructive SQL not allowed",
        ))
        result = engine.check_guardrails("run_sql", {"query": "delete from users where 1=1"})
        assert result == "Destructive SQL not allowed"

    def test_regex_no_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="query",
            match_type="regex", pattern=r"(?i)\b(DROP|DELETE|TRUNCATE)\b",
            message="Destructive SQL not allowed",
        ))
        result = engine.check_guardrails("run_sql", {"query": "SELECT * FROM users"})
        assert result is None


class TestGuardrailWildcard:
    def test_wildcard_argument_scans_all_values(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="DANGER",
            message="Dangerous content",
        ))
        result = engine.check_guardrails("any_tool", {
            "safe": "hello",
            "nested": {"deep": "contains DANGER here"},
        })
        assert result == "Dangerous content"

    def test_wildcard_argument_scans_lists(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="bad",
            message="Bad content",
        ))
        result = engine.check_guardrails("tool", {"items": ["good", "bad", "neutral"]})
        assert result == "Bad content"

    def test_wildcard_no_match(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="missing",
            message="Not found",
        ))
        result = engine.check_guardrails("tool", {"a": "hello", "b": "world"})
        assert result is None


class TestGuardrailToolFiltering:
    def test_tool_specific_guardrail_applies(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="dangerous_tool", argument_name="*",
            match_type="contains", pattern="x",
            message="Blocked",
        ))
        result = engine.check_guardrails("dangerous_tool", {"arg": "x"})
        assert result == "Blocked"

    def test_tool_specific_guardrail_skips_other_tools(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="dangerous_tool", argument_name="*",
            match_type="contains", pattern="x",
            message="Blocked",
        ))
        result = engine.check_guardrails("safe_tool", {"arg": "x"})
        assert result is None

    def test_inactive_guardrail_skipped(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="x",
            message="Blocked", active=False,
        ))
        result = engine.check_guardrails("tool", {"arg": "x"})
        assert result is None

    def test_first_violation_wins(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="a",
            message="First",
        ))
        engine.add_guardrail(ArgumentGuardrail(
            id=2, tool_name="*", argument_name="*",
            match_type="contains", pattern="b",
            message="Second",
        ))
        result = engine.check_guardrails("tool", {"arg": "a and b"})
        assert result == "First"


class TestGuardrailCRUD:
    def test_remove_guardrail(self, engine):
        engine.add_guardrail(ArgumentGuardrail(
            id=1, tool_name="*", argument_name="*",
            match_type="contains", pattern="x", message="Blocked",
        ))
        engine.remove_guardrail(1)
        result = engine.check_guardrails("tool", {"arg": "x"})
        assert result is None

    @pytest.mark.anyio
    async def test_store_crud(self, store):
        guardrail = ArgumentGuardrail(
            tool_name="*", argument_name="query",
            match_type="contains", pattern="DROP",
            message="No drops",
        )
        gid = await store.add_guardrail(guardrail, target_name="default")
        assert gid > 0

        guardrails = await store.get_guardrails(target_name="default")
        assert len(guardrails) == 1
        assert guardrails[0].pattern == "DROP"
        assert guardrails[0].message == "No drops"

        updated = await store.update_guardrail(gid, message="Updated message")
        assert updated
        guardrails = await store.get_guardrails(target_name="default")
        assert guardrails[0].message == "Updated message"

        deleted = await store.delete_guardrail(gid)
        assert deleted
        guardrails = await store.get_guardrails(target_name="default")
        assert len(guardrails) == 0
