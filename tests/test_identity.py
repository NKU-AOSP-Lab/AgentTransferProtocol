"""Tests for atp.core.identity."""

import pytest

from atp.core.errors import MessageFormatError
from atp.core.identity import AgentID


class TestAgentIDParsing:
    """Test AgentID.parse() with valid and invalid inputs."""

    def test_parse_simple(self):
        aid = AgentID.parse("alice@example.com")
        assert aid.local_part == "alice"
        assert aid.domain == "example.com"

    def test_parse_with_dots(self):
        aid = AgentID.parse("bot.v2@service.org")
        assert aid.local_part == "bot.v2"
        assert aid.domain == "service.org"

    def test_parse_with_plus(self):
        aid = AgentID.parse("a+b@host.co")
        assert aid.local_part == "a+b"
        assert aid.domain == "host.co"

    def test_parse_with_hyphen_underscore(self):
        aid = AgentID.parse("my-agent_1@domain.io")
        assert aid.local_part == "my-agent_1"
        assert aid.domain == "domain.io"

    def test_case_insensitivity(self):
        aid = AgentID.parse("Alice@Example.COM")
        assert aid.local_part == "alice"
        assert aid.domain == "example.com"

    def test_str_representation(self):
        aid = AgentID.parse("alice@example.com")
        assert str(aid) == "alice@example.com"

    def test_str_after_case_normalization(self):
        aid = AgentID.parse("Alice@Example.COM")
        assert str(aid) == "alice@example.com"

    def test_frozen(self):
        aid = AgentID.parse("alice@example.com")
        with pytest.raises(AttributeError):
            aid.local_part = "bob"  # type: ignore[misc]


class TestAgentIDInvalid:
    """Test that invalid agent IDs raise MessageFormatError."""

    def test_empty_string(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("")

    def test_no_at_sign(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("noat")

    def test_no_domain(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("@nodomain")

    def test_no_local_part(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("nolocal@")

    def test_double_at(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("a@@b.com")

    def test_two_at_signs(self):
        with pytest.raises(MessageFormatError):
            AgentID.parse("a@b@c.com")
