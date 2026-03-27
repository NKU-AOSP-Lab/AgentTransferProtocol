"""ATS (Agent Transfer Security) — sender authorization for ATP messages.

Analogous to SPF for email: domain owners publish ATS TXT records that list
which IP addresses and domains are authorized to send on their behalf.
"""

from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass
from typing import Optional

from atp.core.errors import ATSError, ATPErrorCode
from atp.discovery.dns import BaseDNSResolver

logger = logging.getLogger(__name__)


@dataclass
class ATSResult:
    """Outcome of an ATS policy evaluation."""

    status: str  # "PASS" | "FAIL" | "NEUTRAL"
    error_code: Optional[str] = None  # "550 5.7.26" | "451 4.7.26"
    matched_directive: Optional[str] = None


@dataclass
class ATSDirective:
    """A single directive inside an ATS policy."""

    action: str  # "allow" | "deny"
    qualifier: str  # "ip" | "domain" | "all"
    value: str  # CIDR like "192.0.2.0/24", domain like "partner.com", or "all"


class ATSPolicy:
    """Parsed representation of an ATS TXT record."""

    def __init__(self, directives: list[ATSDirective]):
        self.directives = directives

    @classmethod
    def parse(cls, txt_record: str) -> ATSPolicy:
        """Parse ATS TXT record like ``v=atp1 allow=ip:192.0.2.0/24 deny=all``.

        Must start with ``v=atp1``.  Raises :class:`ATSError` if version is
        missing or incorrect.
        """
        tokens = txt_record.strip().split()
        if not tokens or tokens[0] != "v=atp1":
            raise ATSError(
                ATPErrorCode.ATS_SYNTAX_ERROR,
                "ATS record must start with 'v=atp1'",
            )

        directives: list[ATSDirective] = []
        for token in tokens[1:]:
            # include:<record> — not yet supported
            if token.startswith("include:"):
                logger.warning("ATS include directive not yet supported: %s", token)
                continue
            # redirect=<domain> — not yet supported
            if token.startswith("redirect="):
                logger.warning("ATS redirect directive not yet supported: %s", token)
                continue

            # Expected forms: allow=ip:<cidr>, deny=domain:<d>, allow=all, …
            if "=" not in token:
                logger.warning("Skipping unrecognized ATS token: %s", token)
                continue

            action, rest = token.split("=", 1)
            if action not in ("allow", "deny"):
                logger.warning("Skipping unknown action '%s' in token: %s", action, token)
                continue

            if rest == "all":
                directives.append(ATSDirective(action=action, qualifier="all", value="all"))
            elif rest.startswith("ip:"):
                cidr = rest[3:]
                directives.append(ATSDirective(action=action, qualifier="ip", value=cidr))
            elif rest.startswith("domain:"):
                domain = rest[7:]
                directives.append(ATSDirective(action=action, qualifier="domain", value=domain))
            else:
                logger.warning("Skipping unrecognized qualifier in token: %s", token)

        return cls(directives)

    async def evaluate(self, source_ip: str, sender_domain: str, dns_resolver: Optional[BaseDNSResolver] = None) -> ATSResult:
        """Evaluate directives in order; first matching directive wins.

        * **ip** directives — check whether *source_ip* belongs to the CIDR.
        * **domain** directives — resolve the domain to IPs, check if
          *source_ip* matches any of them. This is analogous to SPF's
          ``include`` mechanism: ``allow=domain:relay.example.com`` means
          "allow if the sending server's IP resolves from relay.example.com".
        * **all** — always matches.

        Returns ``ATSResult(status="NEUTRAL")`` when no directive matches.
        """
        for directive in self.directives:
            matched = False
            if directive.qualifier == "ip":
                try:
                    network = ipaddress.ip_network(directive.value, strict=False)
                    addr = ipaddress.ip_address(source_ip)
                    matched = addr in network
                except ValueError:
                    continue
            elif directive.qualifier == "domain":
                # Resolve the authorized domain to IPs and check if
                # source_ip is among them.
                if dns_resolver is not None:
                    try:
                        domain_ips = await dns_resolver.resolve_ips(directive.value)
                        matched = source_ip in domain_ips
                    except Exception:
                        continue
                else:
                    # No resolver available (e.g. unit test) — cannot verify
                    continue
            elif directive.qualifier == "all":
                matched = True

            if matched:
                status = "PASS" if directive.action == "allow" else "FAIL"
                error_code = (
                    ATPErrorCode.ATS_VALIDATION_FAILED.value
                    if status == "FAIL"
                    else None
                )
                directive_str = f"{directive.action}={directive.qualifier}:{directive.value}"
                return ATSResult(
                    status=status,
                    error_code=error_code,
                    matched_directive=directive_str,
                )

        return ATSResult(status="NEUTRAL")


class ATSVerifier:
    """High-level verifier that fetches the ATS record via DNS and evaluates it."""

    def __init__(self, dns_resolver: BaseDNSResolver):
        self._resolver = dns_resolver

    async def verify(self, sender_domain: str, source_ip: str) -> ATSResult:
        """Verify that *source_ip* is authorized to send for *sender_domain*.

        1. Query ``ats._atp.{sender_domain}`` TXT record.
        2. If absent → ``NEUTRAL``.
        3. Parse → evaluate → return result.
        """
        query_name = f"ats._atp.{sender_domain}"
        try:
            txt = await self._resolver.query_txt(query_name)
        except Exception:
            # DNS failure is a temporary error — reject the message so the
            # sender retries later, rather than silently allowing it through.
            return ATSResult(
                status="TEMPERROR",
                error_code=ATPErrorCode.ATS_TEMP_ERROR.value,
            )

        if txt is None:
            return ATSResult(status="NEUTRAL")

        policy = ATSPolicy.parse(txt)
        return await policy.evaluate(source_ip, sender_domain, dns_resolver=self._resolver)
