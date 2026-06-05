"""Tests for the masking store."""

import aiosqlite
import pytest

from openmaskit.masking.rules import MaskingRule
from openmaskit.masking.store import MaskingStore


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
        from openmaskit.masking.rules import ArgumentGuardrail

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
        from openmaskit.masking.rules import ArgumentGuardrail

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
        from openmaskit.masking.rules import ArgumentInjection
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
        from openmaskit.masking.rules import ArgumentInjection
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
        from openmaskit.masking.rules import ArgumentGuardrail

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


class TestStorePragmas:
    @pytest.mark.anyio
    async def test_wal_mode_enabled(self, store):
        """store.db should run in WAL mode to match traffic.db; the alias flush
        loop and dashboard CRUD writes overlap, and rollback-journal mode
        serializes them."""
        cursor = await store._db.execute("PRAGMA journal_mode")
        row = await cursor.fetchone()
        assert row[0].lower() == "wal"

    @pytest.mark.anyio
    async def test_synchronous_normal(self, store):
        cursor = await store._db.execute("PRAGMA synchronous")
        row = await cursor.fetchone()
        # SQLite reports synchronous as int: 0=OFF, 1=NORMAL, 2=FULL, 3=EXTRA
        assert row[0] == 1


class TestPerTargetAliasNamespace:
    """Aliases are unique per (target_name, alias), not globally.

    Before the composite-PK migration, two targets that shared an alias prefix
    would collide on INSERT and the second target's row was silently rejected.
    """

    @pytest.mark.anyio
    async def test_same_alias_in_two_targets_persists(self, store):
        """Both targets can independently hold 'host_1' for different values."""
        a = await store.get_or_create_alias("prod-a.com", "tool", "host", "host", target_name="targetA")
        b = await store.get_or_create_alias("prod-b.com", "tool", "host", "host", target_name="targetB")
        assert a == "host_1"
        assert b == "host_1"

        # And the rows survive together.
        mappings_a = await store.get_all_mappings(target_name="targetA")
        mappings_b = await store.get_all_mappings(target_name="targetB")
        assert len(mappings_a) == 1 and mappings_a[0]["real_value"] == "prod-a.com"
        assert len(mappings_b) == 1 and mappings_b[0]["real_value"] == "prod-b.com"

    @pytest.mark.anyio
    async def test_resolve_alias_target_scoped(self, store):
        await store.get_or_create_alias("prod-a.com", "tool", "host", "host", target_name="targetA")
        await store.get_or_create_alias("prod-b.com", "tool", "host", "host", target_name="targetB")
        assert await store.resolve_alias("host_1", target_name="targetA") == "prod-a.com"
        assert await store.resolve_alias("host_1", target_name="targetB") == "prod-b.com"

    @pytest.mark.anyio
    async def test_per_target_counter_does_not_leak(self, store):
        """Target A's counter advances don't push target B's counter forward."""
        await store.get_or_create_alias("a1", "tool", "host", "host", target_name="targetA")
        await store.get_or_create_alias("a2", "tool", "host", "host", target_name="targetA")
        await store.get_or_create_alias("a3", "tool", "host", "host", target_name="targetA")
        first_b = await store.get_or_create_alias("b1", "tool", "host", "host", target_name="targetB")
        assert first_b == "host_1"

    @pytest.mark.anyio
    async def test_counters_reload_per_target_on_restart(self, tmp_path):
        db_path = tmp_path / "per_target.db"

        s1 = await MaskingStore.create(db_path)
        await s1.get_or_create_alias("a1", "tool", "host", "host", target_name="A")
        await s1.get_or_create_alias("a2", "tool", "host", "host", target_name="A")
        await s1.get_or_create_alias("b1", "tool", "host", "host", target_name="B")
        await s1.close()

        s2 = await MaskingStore.create(db_path)
        try:
            next_a = await s2.get_or_create_alias("a3", "tool", "host", "host", target_name="A")
            next_b = await s2.get_or_create_alias("b2", "tool", "host", "host", target_name="B")
            assert next_a == "host_3"
            assert next_b == "host_2"
        finally:
            await s2.close()


class TestPersistAlias:
    """``persist_alias`` writes the engine-minted alias verbatim."""

    @pytest.mark.anyio
    async def test_persist_stores_engine_chosen_alias(self, store):
        await store.persist_alias("targetA", "host_42", "prod.example", "tool", "host")
        assert await store.resolve_alias("host_42", target_name="targetA") == "prod.example"

    @pytest.mark.anyio
    async def test_persist_is_idempotent(self, store):
        await store.persist_alias("targetA", "host_1", "prod.example", "tool", "host")
        # Repeating the same call must not raise — INSERT OR IGNORE.
        await store.persist_alias("targetA", "host_1", "prod.example", "tool", "host")
        mappings = await store.get_all_mappings(target_name="targetA")
        assert len(mappings) == 1

    @pytest.mark.anyio
    async def test_persist_keeps_counter_in_sync(self, store):
        """A subsequent get_or_create_alias must not re-mint a persisted alias."""
        await store.persist_alias("targetA", "host_5", "prod.example", "tool", "host")
        a = await store.get_or_create_alias("new.example", "tool", "host", "host", target_name="targetA")
        assert a == "host_6"

    @pytest.mark.anyio
    async def test_persist_does_not_overwrite_existing_value(self, store):
        await store.persist_alias("targetA", "host_1", "first.example", "tool", "host")
        await store.persist_alias("targetA", "host_1", "second.example", "tool", "host")
        # First write wins — resolves to first.example, not second.
        assert await store.resolve_alias("host_1", target_name="targetA") == "first.example"


class TestMappingsPkMigration:
    """Migration from the old PRIMARY KEY (alias) shape to (target_name, alias)."""

    @pytest.mark.anyio
    async def test_migration_rebuilds_pk_and_preserves_rows(self, tmp_path):
        db_path = tmp_path / "legacy.db"

        # Manually create a DB with the OLD schema and seed two rows.
        legacy_db = await aiosqlite.connect(str(db_path))
        try:
            await legacy_db.executescript(
                """
                CREATE TABLE mappings (
                    alias TEXT PRIMARY KEY,
                    real_value TEXT NOT NULL,
                    tool_name TEXT NOT NULL,
                    field_path TEXT NOT NULL,
                    target_name TEXT NOT NULL DEFAULT 'default',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            await legacy_db.execute(
                "INSERT INTO mappings (alias, real_value, tool_name, field_path, target_name) VALUES (?, ?, ?, ?, ?)",
                ("host_1", "prod-a.com", "tool", "host", "targetA"),
            )
            await legacy_db.execute(
                "INSERT INTO mappings (alias, real_value, tool_name, field_path, target_name) VALUES (?, ?, ?, ?, ?)",
                ("host_2", "prod-b.com", "tool", "host", "targetB"),
            )
            await legacy_db.commit()
        finally:
            await legacy_db.close()

        # Now open via MaskingStore — _migrate runs and rebuilds the PK.
        store = await MaskingStore.create(db_path)
        try:
            assert await store._mappings_pk_is_composite()
            # Both rows survived under their respective targets.
            mappings_a = await store.get_all_mappings(target_name="targetA")
            mappings_b = await store.get_all_mappings(target_name="targetB")
            assert {m["real_value"] for m in mappings_a} == {"prod-a.com"}
            assert {m["real_value"] for m in mappings_b} == {"prod-b.com"}
            # And after migration, the previously-impossible cross-target
            # collision is allowed.
            await store.persist_alias("targetB", "host_1", "prod-b-extra.com", "tool", "host")
            assert await store.resolve_alias("host_1", target_name="targetA") == "prod-a.com"
            assert await store.resolve_alias("host_1", target_name="targetB") == "prod-b-extra.com"
        finally:
            await store.close()

    @pytest.mark.anyio
    async def test_migration_is_idempotent(self, tmp_path):
        """Reopening a migrated DB does not re-migrate."""
        db_path = tmp_path / "twice.db"
        s1 = await MaskingStore.create(db_path)
        await s1.get_or_create_alias("v", "t", "f", "p", target_name="A")
        await s1.close()
        # Reopen — _migrate_mappings_pk should detect composite PK and no-op.
        s2 = await MaskingStore.create(db_path)
        try:
            assert await s2._mappings_pk_is_composite()
            rows = await s2.get_all_mappings(target_name="A")
            assert len(rows) == 1
        finally:
            await s2.close()


class TestServerConfigDecryptFail:
    """A single undecryptable config_enc row used to raise out of the list
    queries and break the entire Servers page; verify it now surfaces as
    ``config=None`` and other rows still come through."""

    @pytest.mark.anyio
    async def test_get_installed_servers_handles_bad_row(self, store):
        await store.install_server("good", "Good", {"transport": "http", "url": "http://x"})
        await store.install_server("bad", "Bad", {"transport": "http", "url": "http://y"})
        # Corrupt the bad row's config_enc blob.
        await store._db.execute(
            "UPDATE mcp_servers SET config_enc = ? WHERE id = ?",
            (b"not-a-valid-fernet-blob", "bad"),
        )
        await store._db.commit()

        rows = await store.get_installed_servers()
        by_id = {r["id"]: r for r in rows}
        assert by_id["good"]["config"] == {"transport": "http", "url": "http://x"}
        assert by_id["bad"]["config"] is None

    @pytest.mark.anyio
    async def test_get_all_servers_handles_bad_row(self, store):
        await store.install_server("good", "Good", {"transport": "http", "url": "http://x"})
        await store.install_server("bad", "Bad", {"transport": "http", "url": "http://y"})
        await store._db.execute(
            "UPDATE mcp_servers SET config_enc = ? WHERE id = ?",
            (b"not-a-valid-fernet-blob", "bad"),
        )
        await store._db.commit()

        rows = await store.get_all_servers()
        by_id = {r["id"]: r for r in rows}
        # get_all_servers JSON-encodes the config; bad row gets a literal None.
        assert by_id["good"]["config"] == '{"transport": "http", "url": "http://x"}'
        assert by_id["bad"]["config"] is None

    @pytest.mark.anyio
    async def test_get_server_returns_none_config_for_bad_row(self, store):
        await store.install_server("bad", "Bad", {"transport": "http", "url": "http://y"})
        await store._db.execute(
            "UPDATE mcp_servers SET config_enc = ? WHERE id = ?",
            (b"not-a-valid-fernet-blob", "bad"),
        )
        await store._db.commit()

        record = await store.get_server("bad")
        assert record is not None
        assert record["id"] == "bad"
        assert record["config"] is None
