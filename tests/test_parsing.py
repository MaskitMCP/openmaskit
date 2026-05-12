"""Tests for Python repr parsing support."""

from __future__ import annotations

from maskit.masking.parsing import _convert_tuples, try_parse_structured


class TestTryParseStructured:
    def test_valid_json_dict(self):
        result = try_parse_structured('{"key": "value", "num": 42}')
        assert result is not None
        assert result.format == "json"
        assert result.data == {"key": "value", "num": 42}

    def test_valid_json_array(self):
        result = try_parse_structured('[1, 2, 3]')
        assert result is not None
        assert result.format == "json"
        assert result.data == [1, 2, 3]

    def test_python_dict_single_quotes(self):
        result = try_parse_structured("{'host': 'prod-db.com', 'port': 5432}")
        assert result is not None
        assert result.format == "python_repr"
        assert result.data == {"host": "prod-db.com", "port": 5432}

    def test_python_booleans(self):
        result = try_parse_structured("{'active': True, 'deleted': False, 'value': None}")
        assert result is not None
        assert result.format == "python_repr"
        assert result.data == {"active": True, "deleted": False, "value": None}

    def test_python_tuple(self):
        result = try_parse_structured("('a', 'b', 'c')")
        assert result is not None
        assert result.format == "python_repr"
        assert result.data == ["a", "b", "c"]

    def test_nested_python_dict(self):
        text = "{'connection': {'host': '10.0.0.1', 'credentials': {'user': 'admin', 'pass': 'secret'}}}"
        result = try_parse_structured(text)
        assert result is not None
        assert result.format == "python_repr"
        assert result.data["connection"]["credentials"]["pass"] == "secret"

    def test_plain_text_returns_none(self):
        result = try_parse_structured("just some plain text")
        assert result is None

    def test_invalid_syntax_returns_none(self):
        result = try_parse_structured("{'unclosed: dict")
        assert result is None

    def test_empty_string_returns_none(self):
        result = try_parse_structured("")
        assert result is None

    def test_scalar_values_rejected(self):
        result = try_parse_structured("42")
        assert result is None

    def test_python_list_of_dicts(self):
        text = "[{'id': 1, 'name': 'Alice'}, {'id': 2, 'name': 'Bob'}]"
        result = try_parse_structured(text)
        assert result is not None
        assert result.format == "python_repr"
        assert result.data[0]["name"] == "Alice"

    def test_json_preferred_over_python(self):
        text = '["a", "b"]'
        result = try_parse_structured(text)
        assert result is not None
        assert result.format == "json"


class TestConvertTuples:
    def test_nested_tuple(self):
        assert _convert_tuples((1, (2, 3))) == [1, [2, 3]]

    def test_tuple_in_dict(self):
        assert _convert_tuples({"coords": (1, 2)}) == {"coords": [1, 2]}

    def test_no_tuples_unchanged(self):
        assert _convert_tuples({"a": [1, 2]}) == {"a": [1, 2]}
