"""Tests for Python repr parsing support."""

from __future__ import annotations

from openmaskit.masking.parsing import (
    DEFAULT_MAX_PARSE_LEN,
    _convert_tuples,
    get_max_parse_len,
    try_parse_structured,
)


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


class TestSizeCap:
    """Defense against a malicious upstream returning a huge nested literal."""

    def test_oversized_input_rejected(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "100")
        text = "[" + ",".join(['"x"'] * 200) + "]"  # well over 100 chars
        assert try_parse_structured(text) is None

    def test_under_limit_still_parses(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "100")
        result = try_parse_structured('{"k": "v"}')
        assert result is not None
        assert result.data == {"k": "v"}

    def test_exactly_at_limit_parses(self, monkeypatch):
        text = '{"a":1}'
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", str(len(text)))
        result = try_parse_structured(text)
        assert result is not None
        assert result.data == {"a": 1}

    def test_python_repr_path_also_capped(self, monkeypatch):
        """The literal_eval branch is the real motivation for the cap."""
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "100")
        text = "{'items': [" + ",".join(["'x'"] * 200) + "]}"
        assert try_parse_structured(text) is None


class TestGetMaxParseLen:
    def test_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("OPENMASKIT_MAX_PARSE_BYTES", raising=False)
        assert get_max_parse_len() == DEFAULT_MAX_PARSE_LEN

    def test_env_override(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "2048")
        assert get_max_parse_len() == 2048

    def test_non_numeric_falls_back(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "lots")
        assert get_max_parse_len() == DEFAULT_MAX_PARSE_LEN

    def test_non_positive_falls_back(self, monkeypatch):
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "0")
        assert get_max_parse_len() == DEFAULT_MAX_PARSE_LEN
        monkeypatch.setenv("OPENMASKIT_MAX_PARSE_BYTES", "-1")
        assert get_max_parse_len() == DEFAULT_MAX_PARSE_LEN


class TestConvertTuples:
    def test_nested_tuple(self):
        assert _convert_tuples((1, (2, 3))) == [1, [2, 3]]

    def test_tuple_in_dict(self):
        assert _convert_tuples({"coords": (1, 2)}) == {"coords": [1, 2]}

    def test_no_tuples_unchanged(self):
        assert _convert_tuples({"a": [1, 2]}) == {"a": [1, 2]}
