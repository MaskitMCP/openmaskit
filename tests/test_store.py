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
