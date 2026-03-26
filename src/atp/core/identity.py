"""Agent identity representation and parsing."""

import re
from dataclasses import dataclass

from atp.core.errors import ATPErrorCode, MessageFormatError

# local_part: alphanumeric, dot, hyphen, underscore, plus
_LOCAL_PART_RE = re.compile(r"^[a-zA-Z0-9._+\-]+$")

# domain: valid hostname (labels separated by dots, each label alphanumeric/hyphen,
# not starting or ending with hyphen, at least two labels)
_DOMAIN_RE = re.compile(
    r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(\.[a-zA-Z0-9-]{1,63})*$"
)


@dataclass(frozen=True)
class AgentID:
    """Represents an agent identity in the form local_part@domain."""

    local_part: str  # stored as lowercase
    domain: str

    @classmethod
    def parse(cls, agent_id: str) -> "AgentID":
        """Parse 'local@domain'.

        Case-insensitive local_part. Raises MessageFormatError on invalid format.
        """
        if not agent_id or not isinstance(agent_id, str):
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Invalid agent ID: {agent_id!r}",
            )

        parts = agent_id.split("@")
        if len(parts) != 2:
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Agent ID must contain exactly one '@': {agent_id!r}",
            )

        local_part, domain = parts

        if not local_part:
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Agent ID local part cannot be empty: {agent_id!r}",
            )

        if not domain:
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Agent ID domain cannot be empty: {agent_id!r}",
            )

        if not _LOCAL_PART_RE.match(local_part):
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Invalid characters in local part: {local_part!r}",
            )

        if not _DOMAIN_RE.match(domain):
            raise MessageFormatError(
                ATPErrorCode.INVALID_MESSAGE_FORMAT,
                f"Invalid domain: {domain!r}",
            )

        return cls(local_part=local_part.lower(), domain=domain.lower())

    def __str__(self) -> str:
        """Return 'local_part@domain'."""
        return f"{self.local_part}@{self.domain}"
