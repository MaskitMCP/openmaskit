"""Tests for the masking engine."""

import ast
import json

import pytest
import pytest_asyncio

from openmaskit.masking.engine import MaskingEngine
from openmaskit.masking.mappers import ResponseMapper
from openmaskit.masking.rules import MaskingRule, delete_nested_value, get_nested_value, set_nested_value
from openmaskit.masking.store import MaskingStore


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


class TestPythonReprMasking:
    @pytest.mark.anyio
    async def test_mask_python_repr_text_content(self, engine):
        result = {
            "content": [
                {
                    "type": "text",
                    "text": "{'host': 'prod-db.example.com', 'port': 5432}",
                }
            ]
        }
        masked = engine.mask_response("get_connection", result)
        parsed = ast.literal_eval(masked["content"][0]["text"])
        assert parsed["host"] == "host_1"
        assert parsed["port"] == 5432

    @pytest.mark.anyio
    async def test_json_field_mask_on_python_repr(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="host", alias_prefix="server",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": "{'host': 'internal.server.net', 'port': 3306}"}]}
        masked = engine.mask_response("test_tool", result)
        data = ast.literal_eval(masked["content"][0]["text"])
        assert data["host"] == "server_1"

    @pytest.mark.anyio
    async def test_python_booleans_and_none_passthrough(self, engine):
        result = {
            "content": [
                {
                    "type": "text",
                    "text": "{'host': 'my-host.net', 'active': True, 'deleted': None}",
                }
            ]
        }
        masked = engine.mask_response("get_connection", result)
        parsed = ast.literal_eval(masked["content"][0]["text"])
        assert parsed["host"] == "host_1"
        assert parsed["active"] is True
        assert parsed["deleted"] is None

    @pytest.mark.anyio
    async def test_json_input_stays_json(self, engine):
        result = {
            "content": [
                {
                    "type": "text",
                    "text": '{"host": "prod-db.example.com", "port": 5432}',
                }
            ]
        }
        masked = engine.mask_response("get_connection", result)
        parsed = json.loads(masked["content"][0]["text"])
        assert parsed["host"] == "host_1"

    @pytest.mark.anyio
    async def test_overlapping_alias_names_unmask_correctly(self, engine):
        """Aliases like cred_1 and cred_10 should not collide during unmasking."""
        result1 = {
            "content": [{"type": "text", "text": '{"host": "first.example.com"}'}]
        }
        result2 = {
            "content": [{"type": "text", "text": '{"host": "second.example.com"}'}]
        }
        # Create host_1 and host_2 (or more) aliases
        for i in range(11):
            r = {
                "content": [
                    {"type": "text", "text": json.dumps({"host": f"host{i}.example.com"})}
                ]
            }
            engine.mask_response("get_connection", r)

        # Now host_1 through host_11 exist as aliases. Unmask host_10 correctly.
        args = {"host": "host_10"}
        unmasked = engine.unmask_arguments("get_connection", args)
        assert unmasked["host"] == "host9.example.com"

        # Ensure host_1 unmasks to its own value, not partial match of host_10
        args2 = {"host": "host_1"}
        unmasked2 = engine.unmask_arguments("get_connection", args2)
        assert unmasked2["host"] == "host0.example.com"

    @pytest.mark.anyio
    async def test_unmask_alias_embedded_in_string(self, engine):
        """Aliases embedded in longer strings should unmask correctly."""
        result = {
            "content": [{"type": "text", "text": '{"host": "prod-db.internal.net"}'}]
        }
        engine.mask_response("get_connection", result)
        # host_1 = prod-db.internal.net
        args = {"query": "SELECT * FROM host_1:5432/mydb"}
        unmasked = engine.unmask_arguments("get_connection", args)
        assert unmasked["query"] == "SELECT * FROM prod-db.internal.net:5432/mydb"

    @pytest.mark.anyio
    async def test_empty_text_block_unchanged(self, engine):
        result = {"content": [{"type": "text", "text": ""}]}
        masked = engine.mask_response("get_connection", result)
        assert masked["content"][0]["text"] == ""

    @pytest.mark.anyio
    async def test_non_text_block_unchanged(self, engine):
        result = {"content": [{"type": "image", "data": "base64stuff"}]}
        masked = engine.mask_response("get_connection", result)
        assert masked["content"][0] == {"type": "image", "data": "base64stuff"}


class TestDeleteNestedValue:
    def test_delete_simple(self):
        data = {"host": "mydb.com", "port": 5432}
        assert delete_nested_value(data, "host")
        assert "host" not in data
        assert data["port"] == 5432

    def test_delete_nested(self):
        data = {"connection": {"password": "secret", "host": "db.com"}}
        assert delete_nested_value(data, "connection.password")
        assert "password" not in data["connection"]
        assert data["connection"]["host"] == "db.com"

    def test_delete_missing_returns_false(self):
        data = {"foo": "bar"}
        assert not delete_nested_value(data, "missing")

    def test_delete_missing_nested_returns_false(self):
        data = {"foo": {"bar": "baz"}}
        assert not delete_nested_value(data, "foo.missing")


class TestStripAction:
    @pytest.mark.anyio
    async def test_strip_removes_field_from_structured_content(self, store):
        rules = [
            MaskingRule(tool_name="get_user", field_path="ssn", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {"name": "Alice", "ssn": "123-45-6789", "email": "a@b.com"}
        }
        masked = engine.mask_response("get_user", result)
        assert "ssn" not in masked["structuredContent"]
        assert masked["structuredContent"]["name"] == "Alice"
        assert masked["structuredContent"]["email"] == "a@b.com"

    @pytest.mark.anyio
    async def test_strip_removes_field_from_text_json(self, store):
        rules = [
            MaskingRule(tool_name="get_user", field_path="secret", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "content": [{"type": "text", "text": '{"name": "Bob", "secret": "hunter2"}'}]
        }
        masked = engine.mask_response("get_user", result)
        parsed = json.loads(masked["content"][0]["text"])
        assert "secret" not in parsed
        assert parsed["name"] == "Bob"

    @pytest.mark.anyio
    async def test_strip_creates_no_alias(self, store):
        rules = [
            MaskingRule(tool_name="get_user", field_path="ssn", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {"name": "Alice", "ssn": "123-45-6789"}
        }
        engine.mask_response("get_user", result)
        assert len(engine.alias_cache) == 0
        assert not engine.has_pending_writes

    @pytest.mark.anyio
    async def test_strip_nested_field(self, store):
        rules = [
            MaskingRule(tool_name="*", field_path="user.internal_id", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {"user": {"name": "Alice", "internal_id": "abc123"}}
        }
        masked = engine.mask_response("any_tool", result)
        assert "internal_id" not in masked["structuredContent"]["user"]
        assert masked["structuredContent"]["user"]["name"] == "Alice"

    @pytest.mark.anyio
    async def test_strip_removes_field_from_every_dict_in_list_text(self, store):
        rules = [
            MaskingRule(tool_name="list_users", field_path="email", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        # Python-repr list of dicts — the shape the user hit
        text = (
            "[{'id': 1, 'name': 'John Krasinsky', 'email': 'user1@yahoo.com', 'phone_number': None}, "
            "{'id': 2, 'name': 'John Doe', 'email': 'john.doe@gmail.com', 'phone_number': '+31_phone_1'}]"
        )
        result = {"content": [{"type": "text", "text": text}]}
        masked = engine.mask_response("list_users", result)
        parsed = ast.literal_eval(masked["content"][0]["text"])
        assert isinstance(parsed, list) and len(parsed) == 2
        for item in parsed:
            assert "email" not in item
        assert parsed[0]["name"] == "John Krasinsky"
        assert parsed[1]["name"] == "John Doe"

    @pytest.mark.anyio
    async def test_mask_applies_to_every_dict_in_list_text(self, store):
        rules = [
            MaskingRule(tool_name="list_users", field_path="email", alias_prefix="email"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        text = (
            '[{"id": 1, "email": "a@x.com"}, '
            '{"id": 2, "email": "b@x.com"}, '
            '{"id": 3, "email": "a@x.com"}]'
        )
        result = {"content": [{"type": "text", "text": text}]}
        masked = engine.mask_response("list_users", result)
        parsed = json.loads(masked["content"][0]["text"])
        assert parsed[0]["email"] == "email_1"
        assert parsed[1]["email"] == "email_2"
        # same real value → same alias (cache dedup)
        assert parsed[2]["email"] == "email_1"

    @pytest.mark.anyio
    async def test_strip_on_list_structured_content(self, store):
        rules = [
            MaskingRule(tool_name="list_users", field_path="email", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": [
                {"id": 1, "email": "a@x.com"},
                {"id": 2, "email": "b@x.com"},
            ]
        }
        masked = engine.mask_response("list_users", result)
        for item in masked["structuredContent"]:
            assert "email" not in item

    @pytest.mark.anyio
    async def test_strip_and_mask_combined(self, store):
        rules = [
            MaskingRule(tool_name="*", field_path="password", action="strip"),
            MaskingRule(tool_name="*", field_path="host", alias_prefix="host"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {"host": "prod.db.com", "password": "secret123", "port": 5432}
        }
        masked = engine.mask_response("get_conn", result)
        assert "password" not in masked["structuredContent"]
        assert masked["structuredContent"]["host"] == "host_1"
        assert masked["structuredContent"]["port"] == 5432


class TestRulePathsFanOutOverLists:
    """A rule's field_path must traverse implicitly through list-typed
    intermediate values, so `categories.id` reaches every `id` inside
    `{"categories": [...]}`."""

    @pytest.mark.anyio
    async def test_rule_path_through_nested_list(self, store):
        rules = [
            MaskingRule(tool_name="*", field_path="categories.id", alias_prefix="cat_id"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {
                "categories": [
                    {"id": "alpha", "name": "Dressuurpaard"},
                    {"id": "beta", "name": "Springpaard"},
                ]
            }
        }
        masked = engine.mask_response("list_categories", result)
        masked_ids = [c["id"] for c in masked["structuredContent"]["categories"]]
        assert masked_ids == ["cat_id_1", "cat_id_2"]
        # Sibling fields are untouched.
        assert masked["structuredContent"]["categories"][0]["name"] == "Dressuurpaard"

    @pytest.mark.anyio
    async def test_rule_path_through_two_list_levels(self, store):
        rules = [
            MaskingRule(tool_name="*", field_path="a.b.c", alias_prefix="leaf"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {
                "a": {"b": [{"c": "x"}, {"c": "y"}, {"c": "z"}]},
            }
        }
        masked = engine.mask_response("any_tool", result)
        cs = [item["c"] for item in masked["structuredContent"]["a"]["b"]]
        assert cs == ["leaf_1", "leaf_2", "leaf_3"]

    @pytest.mark.anyio
    async def test_rule_path_plain_dict_still_works(self, store):
        """Regression: paths that don't pass through any list must keep working."""
        rules = [
            MaskingRule(tool_name="*", field_path="connection.password", alias_prefix="secret"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {"connection": {"password": "hunter2", "port": 5432}}
        }
        masked = engine.mask_response("get_conn", result)
        assert masked["structuredContent"]["connection"]["password"] == "secret_1"
        assert masked["structuredContent"]["connection"]["port"] == 5432

    @pytest.mark.anyio
    async def test_rule_path_leaves_non_string_scalars_untouched(self, store):
        """Non-string leaves (int/float/bool) are intentionally NOT masked by
        rules: stringifying them would change the field's type on the unmask
        round-trip, breaking strictly-typed upstream tools. This is the
        current contract; revisit when the cache carries original-type info."""
        rules = [
            MaskingRule(tool_name="*", field_path="categories.id", alias_prefix="cat_id"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {
                "categories": [
                    {"id": 1, "name": "Dressuurpaard"},
                    {"id": 2, "name": "Springpaard"},
                ]
            }
        }
        masked = engine.mask_response("list_categories", result)
        ids = [c["id"] for c in masked["structuredContent"]["categories"]]
        assert ids == [1, 2]  # unchanged

    @pytest.mark.anyio
    async def test_rule_strip_fans_out_over_lists(self, store):
        rules = [
            MaskingRule(tool_name="*", field_path="users.password", action="strip"),
        ]
        engine = MaskingEngine(rules, store)
        await engine.load_aliases()

        result = {
            "structuredContent": {
                "users": [
                    {"name": "amin", "password": "p1"},
                    {"name": "claude", "password": "p2"},
                ]
            }
        }
        masked = engine.mask_response("list_users", result)
        for u in masked["structuredContent"]["users"]:
            assert "password" not in u


class TestRegexMapperOnStructuredContent:
    """Regex mappers must scan structuredContent, not just text blocks."""

    @pytest.mark.anyio
    async def test_regex_mapper_masks_string_leaves_in_structured(self, store):
        engine = MaskingEngine([], store)
        await engine.load_aliases()

        mapper = ResponseMapper(
            id=1,
            tool_name="*",
            mapper_type="regex_replace",
            pattern=r"\bsk-[a-z0-9]+\b",
            alias_prefix="api_key",
            order=0,
        )
        engine.add_mapper(mapper)

        result = {
            "structuredContent": {
                "items": [
                    {"name": "openai", "token": "sk-abc123"},
                    {"name": "anthropic", "token": "sk-xyz789"},
                ]
            }
        }
        masked = engine.mask_response("list_keys", result)
        tokens = [item["token"] for item in masked["structuredContent"]["items"]]
        assert tokens == ["api_key_1", "api_key_2"]

    @pytest.mark.anyio
    async def test_regex_mapper_skips_structured_when_pattern_does_not_match(self, store):
        engine = MaskingEngine([], store)
        await engine.load_aliases()

        mapper = ResponseMapper(
            id=1,
            tool_name="*",
            mapper_type="regex_replace",
            pattern=r"NEVER_MATCHES",
            alias_prefix="x",
            order=0,
        )
        engine.add_mapper(mapper)

        result = {"structuredContent": {"items": [{"token": "sk-abc"}]}}
        masked = engine.mask_response("list_keys", result)
        assert masked["structuredContent"]["items"][0]["token"] == "sk-abc"

    @pytest.mark.anyio
    async def test_regex_mapper_runs_on_both_text_block_and_structured(self, store):
        """Regression for the preview/live divergence: when the response has
        BOTH a text block and structuredContent, the regex must apply to both
        surfaces (same as the preview's flattened view implied)."""
        engine = MaskingEngine([], store)
        await engine.load_aliases()

        mapper = ResponseMapper(
            id=1,
            tool_name="*",
            mapper_type="regex_replace",
            pattern=r"\bsecret_\d+\b",
            alias_prefix="leak",
            order=0,
        )
        engine.add_mapper(mapper)

        result = {
            "content": [
                {"type": "text", "text": "Found secret_111 in the log."},
            ],
            "structuredContent": {"hit": "secret_222"},
        }
        masked = engine.mask_response("scan", result)
        text = masked["content"][0]["text"]
        structured_hit = masked["structuredContent"]["hit"]
        # Both surfaces must be masked, and the same real value must dedupe
        # to the same alias (single counter, single cache).
        assert "secret_111" not in text
        assert "secret_222" not in structured_hit
        assert structured_hit.startswith("leak_")
        assert "leak_" in text
