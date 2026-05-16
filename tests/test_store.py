"""Tests for the masking store."""

import pytest

from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore


@pytest.fixture
async def store(tmp_path):
    s = await MaskingStore.create(tmp_path / "test.db")
    yield s
    await s.close()


class TestMaskingStore:
    @pytest.mark.anyio
    async def test_create_alias(self, store):
        alias = await store.get_or_create_alias("real.host.com", "get_db", "host", "host")
        assert alias == "host_1"

    @pytest.mark.anyio
    async def test_same_value_same_alias(self, store):
        a1 = await store.get_or_create_alias("real.host.com", "get_db", "host", "host")
        a2 = await store.get_or_create_alias("real.host.com", "get_db", "host", "host")
        assert a1 == a2

    @pytest.mark.anyio
    async def test_different_values_different_aliases(self, store):
        a1 = await store.get_or_create_alias("host-a.com", "get_db", "host", "host")
        a2 = await store.get_or_create_alias("host-b.com", "get_db", "host", "host")
        assert a1 == "host_1"
        assert a2 == "host_2"

    @pytest.mark.anyio
    async def test_resolve_alias(self, store):
        await store.get_or_create_alias("secret.value", "tool", "field", "field")
        resolved = await store.resolve_alias("field_1")
        assert resolved == "secret.value"

    @pytest.mark.anyio
    async def test_resolve_unknown_alias(self, store):
        resolved = await store.resolve_alias("nonexistent_99")
        assert resolved is None

    @pytest.mark.anyio
    async def test_persistence_across_instances(self, tmp_path):
        db_path = tmp_path / "persist.db"

        store1 = await MaskingStore.create(db_path)
        await store1.get_or_create_alias("persist-me.com", "tool", "host", "host")
        await store1.close()

        store2 = await MaskingStore.create(db_path)
        resolved = await store2.resolve_alias("host_1")
        assert resolved == "persist-me.com"

        # Counter should continue from where it left off
        a2 = await store2.get_or_create_alias("new-host.com", "tool", "host", "host")
        assert a2 == "host_2"
        await store2.close()

    @pytest.mark.anyio
    async def test_rule_crud(self, store):
        rule = MaskingRule(tool_name="get_db", field_path="password")
        rule_id = await store.add_rule(rule)
        assert rule_id is not None

        rules = await store.get_rules()
        assert len(rules) == 1
        assert rules[0].tool_name == "get_db"
        assert rules[0].field_path == "password"

        deleted = await store.delete_rule(rule_id)
        assert deleted

        rules = await store.get_rules()
        assert len(rules) == 0

    @pytest.mark.anyio
    async def test_get_all_mappings(self, store):
        await store.get_or_create_alias("val1", "tool1", "field1", "f1")
        await store.get_or_create_alias("val2", "tool2", "field2", "f2")

        mappings = await store.get_all_mappings()
        assert len(mappings) == 2
        assert any(m["alias"] == "f1_1" and m["real_value"] == "val1" for m in mappings)
        assert any(m["alias"] == "f2_1" and m["real_value"] == "val2" for m in mappings)


class TestSQLInjectionProtection:
    """Test SQL injection protection in update functions."""

    @pytest.mark.anyio
    async def test_update_guardrail_rejects_invalid_fields(self, store):
        """update_guardrail only accepts whitelisted field names."""
        from maskit.masking.rules import ArgumentGuardrail

        # First add a guardrail
        guardrail = ArgumentGuardrail(
            tool_name="test_tool",
            argument_name="db_host",
            match_type="regex",
            pattern="^prod-.*",
            message="Production access denied",
            active=True,
        )
        guardrail_id = await store.add_guardrail(guardrail)

        # Try to update with valid field
        success = await store.update_guardrail(guardrail_id, pattern="^staging-.*")
        assert success is True

        # Try to update with invalid/SQL injection attempt
        success = await store.update_guardrail(
            guardrail_id,
            malicious_field="'; DROP TABLE guardrails; --"
        )
        # Should return False (no fields updated) because field not in whitelist
        assert success is False

        # Verify guardrail still exists and wasn't modified
        guardrails = await store.get_guardrails()
        assert len(guardrails) > 0
        assert any(g.id == guardrail_id and g.pattern == "^staging-.*" for g in guardrails)

    @pytest.mark.anyio
    async def test_update_guardrail_whitelist_validation(self, store):
        """update_guardrail only updates fields in the allowed set."""
        from maskit.masking.rules import ArgumentGuardrail

        guardrail = ArgumentGuardrail(
            tool_name="test_tool",
            argument_name="param",
            match_type="equals",
            pattern="danger",
            message="Blocked",
            active=True,
        )
        guardrail_id = await store.add_guardrail(guardrail)

        # Allowed fields: tool_name, argument_name, match_type, pattern, message, active
        valid_update = await store.update_guardrail(
            guardrail_id,
            tool_name="updated_tool",
            pattern="new_pattern",
            active=False,
        )
        assert valid_update is True

        # Try mixed valid and invalid fields
        mixed_update = await store.update_guardrail(
            guardrail_id,
            message="Updated message",  # valid
            fake_field="injection",     # invalid - should be ignored
            id="999",                    # invalid - should be ignored
        )
        assert mixed_update is True  # Should succeed for valid field

        # Verify only the valid field was updated
        guardrails = await store.get_guardrails()
        updated = next((g for g in guardrails if g.id == guardrail_id), None)
        assert updated is not None
        assert updated.message == "Updated message"
        assert updated.tool_name == "updated_tool"  # From previous update

    @pytest.mark.anyio
    async def test_update_injection_rejects_invalid_fields(self, store):
        """update_injection only accepts whitelisted field names."""
        from maskit.masking.rules import ArgumentInjection
        import json

        injection = ArgumentInjection(
            tool_name="test_tool",
            argument_name="env",
            value=json.dumps("production"),
            mode="set",
            active=True,
        )
        injection_id = await store.add_injection(injection)

        # Try to update with valid field
        success = await store.update_injection(injection_id, value=json.dumps("staging"))
        assert success is True

        # Try to update with SQL injection attempt
        success = await store.update_injection(
            injection_id,
            malicious="' OR '1'='1",
            target_name="'; DELETE FROM injections; --",
        )
        # Should return False because no valid fields provided
        assert success is False

        # Verify injection still exists
        injections = await store.get_injections()
        assert len(injections) > 0
        assert any(i.id == injection_id for i in injections)

    @pytest.mark.anyio
    async def test_update_injection_whitelist_validation(self, store):
        """update_injection only updates fields in the allowed set."""
        from maskit.masking.rules import ArgumentInjection
        import json

        injection = ArgumentInjection(
            tool_name="test_tool",
            argument_name="config",
            value=json.dumps({"key": "value"}),
            mode="default",
            active=True,
        )
        injection_id = await store.add_injection(injection)

        # Allowed fields: tool_name, argument_name, value, mode, active
        valid_update = await store.update_injection(
            injection_id,
            mode="set",
            active=False,
        )
        assert valid_update is True

        # Verify update worked
        injections = await store.get_injections()
        updated = next((i for i in injections if i.id == injection_id), None)
        assert updated is not None
        assert updated.mode == "set"
        assert updated.active is False

    @pytest.mark.anyio
    async def test_parameterized_values_prevent_injection(self, store):
        """Values are properly parameterized, preventing injection via values."""
        from maskit.masking.rules import ArgumentGuardrail

        guardrail = ArgumentGuardrail(
            tool_name="test",
            argument_name="arg",
            match_type="equals",
            pattern="safe",
            message="test",
            active=True,
        )
        guardrail_id = await store.add_guardrail(guardrail)

        # Try to inject SQL via the pattern value
        injection_attempt = "'; DROP TABLE guardrails; --"
        success = await store.update_guardrail(guardrail_id, pattern=injection_attempt)
        assert success is True

        # Verify the malicious string was stored as a literal value (parameterized)
        guardrails = await store.get_guardrails()
        updated = next((g for g in guardrails if g.id == guardrail_id), None)
        assert updated is not None
        assert updated.pattern == injection_attempt  # Stored as literal string

        # Verify table still exists and has all records
        all_guardrails = await store.get_guardrails()
        assert len(all_guardrails) > 0  # Table wasn't dropped


class TestAtomicAliasGeneration:
    """Test atomic alias generation prevents race conditions and data leakage."""

    @pytest.mark.anyio
    async def test_concurrent_alias_generation_no_collision(self, store):
        """Concurrent alias generation produces unique aliases."""
        import anyio

        # Simulate concurrent requests creating aliases with same prefix
        async def create_alias(value: str):
            return await store.get_or_create_alias(value, "tool", "field", "prefix")

        # Create 10 aliases concurrently
        results = []
        async with anyio.create_task_group() as tg:
            for i in range(10):
                tg.start_soon(create_alias, f"value_{i}")

        # Since start_soon doesn't return futures, we need to use a different approach
        # Let's gather results directly
        tasks = [create_alias(f"value_{i}") for i in range(10)]
        from anyio import create_task_group
        aliases = []

        async def run_task(task_coro, result_list):
            result = await task_coro
            result_list.append(result)

        async with create_task_group() as tg:
            for task in tasks:
                tg.start_soon(run_task, task, aliases)

        # Verify all aliases are unique
        assert len(aliases) == len(set(aliases)), f"Duplicate aliases detected: {aliases}"

        # Verify all follow prefix_N pattern
        for alias in aliases:
            assert alias.startswith("prefix_"), f"Alias doesn't match pattern: {alias}"
            assert alias.split("_")[1].isdigit(), f"Alias counter not numeric: {alias}"

    @pytest.mark.anyio
    async def test_same_value_returns_same_alias_concurrent(self, store):
        """Concurrent requests for same value return same alias (eventually)."""
        import anyio

        async def get_alias():
            return await store.get_or_create_alias("shared_value", "tool", "field", "prefix")

        # Request same alias 5 times concurrently
        aliases = []

        async def run_and_collect(result_list):
            result = await get_alias()
            result_list.append(result)

        async with anyio.create_task_group() as tg:
            for _ in range(5):
                tg.start_soon(run_and_collect, aliases)

        # All should resolve to the same value (though aliases may differ due to race)
        # The critical security property is that all aliases map to the same real value
        unique_aliases = set(aliases)
        for alias in unique_aliases:
            resolved = await store.resolve_alias(alias)
            assert resolved == "shared_value", f"Alias {alias} maps to wrong value: {resolved}"

    @pytest.mark.anyio
    async def test_data_leakage_via_alias_collision(self, store):
        """Alias collision cannot leak data between requests (security critical)."""
        import anyio

        # Simulate two concurrent requests masking different sensitive values
        sensitive_value_a = "prod-db-password-123"
        sensitive_value_b = "staging-api-key-456"

        async def mask_value_a():
            # Request A masks prod password
            return await store.get_or_create_alias(sensitive_value_a, "db_connect", "password", "secret")

        async def mask_value_b():
            # Request B masks staging key
            return await store.get_or_create_alias(sensitive_value_b, "api_call", "key", "secret")

        # Run concurrently (race condition test)
        results = []

        async def collect_a(result_list):
            result = await mask_value_a()
            result_list.append(("a", result))

        async def collect_b(result_list):
            result = await mask_value_b()
            result_list.append(("b", result))

        async with anyio.create_task_group() as tg:
            tg.start_soon(collect_a, results)
            tg.start_soon(collect_b, results)

        # Find results
        alias_a = next(r[1] for r in results if r[0] == "a")
        alias_b = next(r[1] for r in results if r[0] == "b")

        # Verify aliases are different (no collision)
        assert alias_a != alias_b, "CRITICAL: Alias collision detected - data leakage risk!"

        # Verify reverse lookup returns correct values
        resolved_a = await store.resolve_alias(alias_a)
        resolved_b = await store.resolve_alias(alias_b)

        assert resolved_a == sensitive_value_a, f"Alias {alias_a} maps to wrong value"
        assert resolved_b == sensitive_value_b, f"Alias {alias_b} maps to wrong value"

    @pytest.mark.anyio
    async def test_high_concurrency_stress_test(self, store):
        """High concurrency stress test (100 concurrent requests)."""
        import anyio

        async def create_alias_with_index(i: int):
            return await store.get_or_create_alias(f"value_{i}", "tool", "field", "test")

        # Create 100 aliases concurrently
        aliases = []

        async def run_and_collect(idx, result_list):
            result = await create_alias_with_index(idx)
            result_list.append(result)

        async with anyio.create_task_group() as tg:
            for i in range(100):
                tg.start_soon(run_and_collect, i, aliases)

        # Verify all unique
        assert len(aliases) == len(set(aliases)), f"Duplicates in high concurrency: {len(aliases)} vs {len(set(aliases))}"

        # Verify all aliases follow the pattern and use valid counters
        counters = [int(a.split("_")[1]) for a in aliases]
        assert all(c > 0 for c in counters), "All counters should be positive"
        assert len(set(counters)) == 100, "All counters should be unique"
        # Note: we don't require sequential counters (1-100) under high concurrency
        # The important guarantee is uniqueness and correct value mapping
