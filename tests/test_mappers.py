"""Tests for response mappers."""

from __future__ import annotations

import pytest

from maskit.masking.engine import MaskingEngine
from maskit.masking.mappers import ResponseMapper
from maskit.masking.rules import MaskingRule
from maskit.masking.store import MaskingStore


@pytest.fixture
async def store(tmp_path):
    db_path = tmp_path / "test.db"
    s = await MaskingStore.create(str(db_path))
    yield s
    await s.close()


@pytest.fixture
async def engine(store):
    e = MaskingEngine([], store)
    await e.load_aliases()
    return e


class TestResponseMapperDataclass:
    def test_matches_tool_exact(self):
        m = ResponseMapper(tool_name="slack_search", mapper_type="regex_replace", pattern="x", alias_prefix="p")
        assert m.matches_tool("slack_search")
        assert not m.matches_tool("other_tool")

    def test_matches_tool_wildcard(self):
        m = ResponseMapper(tool_name="*", mapper_type="regex_replace", pattern="x", alias_prefix="p")
        assert m.matches_tool("anything")


class TestRegexMapperNoGroup:
    async def test_full_match_masked(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "Channel C06GXQV5S58 found"}]}
        masked = engine.mask_response("test_tool", result)
        assert "C06GXQV5S58" not in masked["content"][0]["text"]
        assert "channel_1" in masked["content"][0]["text"]

    async def test_multiple_values_different_aliases(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "C06GXQV5S58 and C017J4YQARH"}]}
        masked = engine.mask_response("test_tool", result)
        text = masked["content"][0]["text"]
        assert "channel_1" in text
        assert "channel_2" in text
        assert "C06GXQV5S58" not in text
        assert "C017J4YQARH" not in text

    async def test_same_value_same_alias(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "C06GXQV5S58 and C06GXQV5S58 again"}]}
        masked = engine.mask_response("test_tool", result)
        text = masked["content"][0]["text"]
        assert text.count("channel_1") == 2


class TestRegexMapperWithGroup:
    async def test_capture_group_only(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"\(([A-Z0-9]+)\)", alias_prefix="id",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "#general (C06GXQV5S58) - public"}]}
        masked = engine.mask_response("test_tool", result)
        text = masked["content"][0]["text"]
        # Surrounding parens should be preserved
        assert "(id_1)" in text
        assert "C06GXQV5S58" not in text
        # Rest of text intact
        assert "#general" in text
        assert "- public" in text


class TestMapperChaining:
    async def test_two_mappers_in_order(self, engine):
        import re
        m1 = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"\(([A-Z0-9]+)\)", alias_prefix="channel", order=0,
        )
        m2 = ResponseMapper(
            id=2, tool_name="*", mapper_type="regex_replace",
            pattern=r"Creator: (\w+)", alias_prefix="user", order=1,
        )
        engine._mappers = [m1, m2]
        engine._compiled_patterns[1] = re.compile(m1.pattern)
        engine._compiled_patterns[2] = re.compile(m2.pattern)

        result = {"content": [{"type": "text", "text": "#edge (C06GXQV5S58) - Creator: Jo"}]}
        masked = engine.mask_response("test_tool", result)
        text = masked["content"][0]["text"]
        assert "channel_1" in text
        assert "user_1" in text
        assert "C06GXQV5S58" not in text
        assert "Creator: user_1" in text


class TestMapperUnmasking:
    async def test_unmask_after_mapper(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "Channel C06GXQV5S58"}]}
        engine.mask_response("test_tool", result)

        # Now unmask
        args = {"channel": "channel_1"}
        unmasked = engine.unmask_arguments("test_tool", args)
        assert unmasked["channel"] == "C06GXQV5S58"


class TestMapperNoMatch:
    async def test_no_match_passthrough(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "text", "text": "nothing to match here"}]}
        masked = engine.mask_response("test_tool", result)
        assert masked["content"][0]["text"] == "nothing to match here"


class TestMapperNonTextBlock:
    async def test_image_block_ignored(self, engine):
        import re
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]{10}", alias_prefix="channel",
        )
        engine._mappers = [mapper]
        engine._compiled_patterns[1] = re.compile(mapper.pattern)

        result = {"content": [{"type": "image", "data": "C06GXQV5S58"}]}
        masked = engine.mask_response("test_tool", result)
        assert masked["content"][0]["data"] == "C06GXQV5S58"


class TestJsonFieldMask:
    async def test_simple_field(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="host", alias_prefix="host",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": '{"host": "prod-db.internal.net", "port": 5432}'}]}
        masked = engine.mask_response("test_tool", result)
        import json
        data = json.loads(masked["content"][0]["text"])
        assert data["host"] == "host_1"
        assert data["port"] == 5432

    async def test_nested_field(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="connection.host", alias_prefix="host",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": '{"connection": {"host": "10.0.0.1", "port": 3306}}'}]}
        masked = engine.mask_response("test_tool", result)
        import json
        data = json.loads(masked["content"][0]["text"])
        assert data["connection"]["host"] == "host_1"
        assert data["connection"]["port"] == 3306

    async def test_array_auto_recurse(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="users.email", alias_prefix="email",
        )
        engine._mappers = [mapper]

        import json
        text = json.dumps({"users": [{"email": "alice@corp.com", "name": "Alice"}, {"email": "bob@corp.com", "name": "Bob"}]})
        result = {"content": [{"type": "text", "text": text}]}
        masked = engine.mask_response("test_tool", result)
        data = json.loads(masked["content"][0]["text"])
        assert data["users"][0]["email"] == "email_1"
        assert data["users"][0]["name"] == "Alice"
        assert data["users"][1]["email"] == "email_2"
        assert data["users"][1]["name"] == "Bob"

    async def test_non_json_passthrough(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="host", alias_prefix="host",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": "not json at all"}]}
        masked = engine.mask_response("test_tool", result)
        assert masked["content"][0]["text"] == "not json at all"

    async def test_missing_path_unchanged(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="nonexistent.field", alias_prefix="val",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": '{"other": "data"}'}]}
        masked = engine.mask_response("test_tool", result)
        assert masked["content"][0]["text"] == '{"other": "data"}'

    async def test_numeric_value_masked(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="secret_port", alias_prefix="port",
        )
        engine._mappers = [mapper]

        result = {"content": [{"type": "text", "text": '{"secret_port": 5432}'}]}
        masked = engine.mask_response("test_tool", result)
        import json
        data = json.loads(masked["content"][0]["text"])
        assert data["secret_port"] == "port_1"

    async def test_same_value_same_alias(self, engine):
        mapper = ResponseMapper(
            id=1, tool_name="*", mapper_type="json_field_mask",
            pattern="items.host", alias_prefix="host",
        )
        engine._mappers = [mapper]

        import json
        text = json.dumps({"items": [{"host": "same.host.com"}, {"host": "same.host.com"}, {"host": "other.host.com"}]})
        result = {"content": [{"type": "text", "text": text}]}
        masked = engine.mask_response("test_tool", result)
        data = json.loads(masked["content"][0]["text"])
        assert data["items"][0]["host"] == "host_1"
        assert data["items"][1]["host"] == "host_1"
        assert data["items"][2]["host"] == "host_2"


class TestStoreMapperCRUD:
    async def test_add_and_get(self, store):
        mapper = ResponseMapper(
            tool_name="slack_search", mapper_type="regex_replace",
            pattern=r"C[A-Z0-9]+", alias_prefix="channel",
        )
        mid = await store.add_mapper(mapper)
        assert mid is not None

        mappers = await store.get_mappers()
        assert len(mappers) == 1
        assert mappers[0].id == mid
        assert mappers[0].tool_name == "slack_search"
        assert mappers[0].pattern == r"C[A-Z0-9]+"

    async def test_delete(self, store):
        mapper = ResponseMapper(
            tool_name="*", mapper_type="regex_replace",
            pattern=r"x", alias_prefix="p",
        )
        mid = await store.add_mapper(mapper)
        assert await store.delete_mapper(mid)
        assert len(await store.get_mappers()) == 0

    async def test_auto_order(self, store):
        m1 = ResponseMapper(tool_name="t", mapper_type="regex_replace", pattern="a", alias_prefix="p")
        m2 = ResponseMapper(tool_name="t", mapper_type="regex_replace", pattern="b", alias_prefix="q")
        await store.add_mapper(m1)
        await store.add_mapper(m2)
        mappers = await store.get_mappers()
        assert mappers[0].order < mappers[1].order

    async def test_reorder(self, store):
        m1 = ResponseMapper(tool_name="t", mapper_type="regex_replace", pattern="a", alias_prefix="p")
        m2 = ResponseMapper(tool_name="t", mapper_type="regex_replace", pattern="b", alias_prefix="q")
        id1 = await store.add_mapper(m1)
        id2 = await store.add_mapper(m2)

        await store.reorder_mappers([id2, id1])
        mappers = await store.get_mappers()
        assert mappers[0].id == id2
        assert mappers[1].id == id1
