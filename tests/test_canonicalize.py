"""Tests for atp.core.canonicalize."""

from atp.core.canonicalize import canonicalize


class TestCanonicalize:
    """Test JCS canonicalization."""

    def test_simple_dict_sorted_keys(self):
        result = canonicalize({"b": 2, "a": 1})
        assert result == b'{"a":1,"b":2}'

    def test_nested_dict_sorted_keys(self):
        result = canonicalize({"z": {"b": 2, "a": 1}, "a": 0})
        assert result == b'{"a":0,"z":{"a":1,"b":2}}'

    def test_empty_dict(self):
        result = canonicalize({})
        assert result == b"{}"

    def test_list_values_preserve_order(self):
        result = canonicalize({"items": [3, 1, 2]})
        assert result == b'{"items":[3,1,2]}'

    def test_list_of_dicts_sorted_keys(self):
        result = canonicalize({"items": [{"b": 2, "a": 1}]})
        assert result == b'{"items":[{"a":1,"b":2}]}'

    def test_string_values(self):
        result = canonicalize({"name": "hello world"})
        assert result == b'{"name":"hello world"}'

    def test_unicode_strings(self):
        result = canonicalize({"greeting": "\u00e9\u00e0\u00fc"})
        # ensure_ascii=False means unicode chars are preserved
        assert result == "\u007b\"greeting\":\"\u00e9\u00e0\u00fc\"\u007d".encode("utf-8")

    def test_boolean_and_null(self):
        result = canonicalize({"a": True, "b": False, "c": None})
        assert result == b'{"a":true,"b":false,"c":null}'

    def test_returns_bytes(self):
        result = canonicalize({"key": "value"})
        assert isinstance(result, bytes)

    def test_no_whitespace(self):
        result = canonicalize({"a": 1, "b": 2, "c": 3})
        decoded = result.decode("utf-8")
        # No spaces around colons or commas
        assert " " not in decoded
