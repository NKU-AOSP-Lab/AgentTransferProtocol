"""Tests for atp.security.ats — ATS policy parsing, evaluation, and verification."""

from __future__ import annotations

import pytest

from atp.core.errors import ATSError
from atp.discovery.dns import BaseDNSResolver, ServerInfo
from atp.security.ats import ATSDirective, ATSPolicy, ATSResult, ATSVerifier


# ── Mock resolver ───────────────────────────────────────────────────────────


class MockResolver(BaseDNSResolver):
    """In-memory resolver for testing."""

    def __init__(
        self,
        txt_records: dict[str, str] | None = None,
        svcb_records: dict[str, ServerInfo] | None = None,
    ):
        self._txt = txt_records or {}
        self._svcb = svcb_records or {}

    async def query_svcb(self, domain: str) -> ServerInfo | None:
        return self._svcb.get(domain)

    async def query_txt(self, name: str) -> str | None:
        return self._txt.get(name)


# ── ATSPolicy.parse ────────────────────────────────────────────────────────


class TestATSPolicyParse:

    def test_valid_record_with_allow_deny_ip_and_all(self):
        policy = ATSPolicy.parse("v=atp1 allow=ip:192.0.2.0/24 deny=all")
        assert len(policy.directives) == 2
        d0 = policy.directives[0]
        assert d0.action == "allow"
        assert d0.qualifier == "ip"
        assert d0.value == "192.0.2.0/24"
        d1 = policy.directives[1]
        assert d1.action == "deny"
        assert d1.qualifier == "all"
        assert d1.value == "all"

    def test_valid_record_with_domain_directive(self):
        policy = ATSPolicy.parse("v=atp1 allow=domain:partner.com deny=all")
        assert len(policy.directives) == 2
        assert policy.directives[0].qualifier == "domain"
        assert policy.directives[0].value == "partner.com"

    def test_raises_on_missing_version(self):
        with pytest.raises(ATSError):
            ATSPolicy.parse("allow=ip:10.0.0.0/8 deny=all")

    def test_raises_on_wrong_version(self):
        with pytest.raises(ATSError):
            ATSPolicy.parse("v=atp2 allow=all")

    def test_raises_on_empty_string(self):
        with pytest.raises(ATSError):
            ATSPolicy.parse("")

    def test_include_and_redirect_are_skipped(self):
        policy = ATSPolicy.parse("v=atp1 include:other.com redirect=other.com allow=all")
        # Only allow=all should survive
        assert len(policy.directives) == 1
        assert policy.directives[0].qualifier == "all"


# ── ATSPolicy.evaluate ─────────────────────────────────────────────────────


class TestATSPolicyEvaluate:

    def test_source_ip_in_allowed_cidr_passes(self):
        policy = ATSPolicy.parse("v=atp1 allow=ip:192.0.2.0/24 deny=all")
        result = policy.evaluate("192.0.2.42", "example.com")
        assert result.status == "PASS"
        assert result.error_code is None

    def test_source_ip_not_in_range_deny_all_fails(self):
        policy = ATSPolicy.parse("v=atp1 allow=ip:192.0.2.0/24 deny=all")
        result = policy.evaluate("10.0.0.1", "example.com")
        assert result.status == "FAIL"
        assert result.error_code == "550 5.7.26"

    def test_domain_exact_match_passes(self):
        policy = ATSPolicy.parse("v=atp1 allow=domain:partner.com deny=all")
        result = policy.evaluate("10.0.0.1", "partner.com")
        assert result.status == "PASS"

    def test_domain_subdomain_match_passes(self):
        policy = ATSPolicy.parse("v=atp1 allow=domain:partner.com deny=all")
        result = policy.evaluate("10.0.0.1", "sub.partner.com")
        assert result.status == "PASS"

    def test_domain_no_match_deny_all(self):
        policy = ATSPolicy.parse("v=atp1 allow=domain:partner.com deny=all")
        result = policy.evaluate("10.0.0.1", "other.com")
        assert result.status == "FAIL"

    def test_no_matching_directive_returns_neutral(self):
        policy = ATSPolicy.parse("v=atp1 allow=ip:192.0.2.0/24")
        result = policy.evaluate("10.0.0.1", "example.com")
        assert result.status == "NEUTRAL"

    def test_localhost_allowed(self):
        policy = ATSPolicy.parse("v=atp1 allow=ip:127.0.0.1/32 deny=all")
        result = policy.evaluate("127.0.0.1", "localhost")
        assert result.status == "PASS"

    def test_allow_all_passes_everything(self):
        policy = ATSPolicy.parse("v=atp1 allow=all")
        result = policy.evaluate("1.2.3.4", "any.domain")
        assert result.status == "PASS"

    def test_deny_all_alone_fails(self):
        policy = ATSPolicy.parse("v=atp1 deny=all")
        result = policy.evaluate("1.2.3.4", "any.domain")
        assert result.status == "FAIL"

    def test_first_matching_directive_wins(self):
        policy = ATSPolicy.parse("v=atp1 deny=ip:10.0.0.0/8 allow=all")
        # IP 10.0.0.1 matches the deny first
        result = policy.evaluate("10.0.0.1", "example.com")
        assert result.status == "FAIL"
        # IP 192.168.1.1 does NOT match deny, so falls through to allow=all
        result = policy.evaluate("192.168.1.1", "example.com")
        assert result.status == "PASS"


# ── ATSVerifier ─────────────────────────────────────────────────────────────


class TestATSVerifier:

    async def test_verify_with_valid_ats_record_pass(self):
        resolver = MockResolver(
            txt_records={
                "ats._atp.sender.com": "v=atp1 allow=ip:192.0.2.0/24 deny=all",
            }
        )
        verifier = ATSVerifier(resolver)
        result = await verifier.verify("sender.com", "192.0.2.10")
        assert result.status == "PASS"

    async def test_verify_with_valid_ats_record_fail(self):
        resolver = MockResolver(
            txt_records={
                "ats._atp.sender.com": "v=atp1 allow=ip:192.0.2.0/24 deny=all",
            }
        )
        verifier = ATSVerifier(resolver)
        result = await verifier.verify("sender.com", "10.0.0.1")
        assert result.status == "FAIL"

    async def test_verify_no_ats_record_returns_neutral(self):
        resolver = MockResolver()
        verifier = ATSVerifier(resolver)
        result = await verifier.verify("unknown.com", "10.0.0.1")
        assert result.status == "NEUTRAL"
        assert result.error_code is None

    async def test_verify_dns_error_returns_neutral_with_temp_error(self):
        class FailingResolver(BaseDNSResolver):
            async def query_svcb(self, domain):
                return None

            async def query_txt(self, name):
                raise Exception("DNS failure")

        verifier = ATSVerifier(FailingResolver())
        result = await verifier.verify("fail.com", "10.0.0.1")
        assert result.status == "NEUTRAL"
        assert result.error_code == "451 4.7.26"
