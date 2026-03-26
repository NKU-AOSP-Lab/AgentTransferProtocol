"""ATP message format and serialization."""

import json
import time
from dataclasses import dataclass, field
from typing import Optional
from uuid import uuid4

from atp.core.errors import ATPErrorCode, MessageFormatError


@dataclass
class SignatureEnvelope:
    """Envelope containing an ATK signature over a message."""

    key_id: str  # e.g. "default.atk._atp.example.com"
    algorithm: str  # "ed25519"
    signature: str  # base64-encoded
    headers: list[str]  # e.g. ["from", "to", "timestamp", "nonce", "type"]
    timestamp: int

    def to_dict(self) -> dict:
        """Serialize the signature envelope to a dictionary."""
        return {
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "signature": self.signature,
            "headers": self.headers,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SignatureEnvelope":
        """Deserialize a signature envelope from a dictionary."""
        return cls(
            key_id=data["key_id"],
            algorithm=data["algorithm"],
            signature=data["signature"],
            headers=data["headers"],
            timestamp=data["timestamp"],
        )


@dataclass
class ATPMessage:
    """An ATP protocol message."""

    from_id: str
    to_id: str
    timestamp: int
    nonce: str  # "msg-{uuid4_hex[:12]}"
    type: str  # always "message"
    payload: dict
    signature: Optional[SignatureEnvelope] = None
    cc: list[str] = field(default_factory=list)
    routing: Optional[dict] = None

    @classmethod
    def create(
        cls,
        from_id: str,
        to_id: str,
        payload: dict,
        cc: list[str] | None = None,
    ) -> "ATPMessage":
        """Create a new ATPMessage with auto-filled timestamp, nonce, and type."""
        return cls(
            from_id=from_id,
            to_id=to_id,
            timestamp=int(time.time()),
            nonce=f"msg-{uuid4().hex[:12]}",
            type="message",
            payload=payload,
            cc=cc or [],
        )

    def to_dict(self) -> dict:
        """Serialize to dict.

        Uses "from" and "to" as keys (matching the protocol spec).
        Omits None/empty optional fields.
        """
        d: dict = {
            "from": self.from_id,
            "to": self.to_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
            "type": self.type,
            "payload": self.payload,
        }
        if self.signature is not None:
            d["signature"] = self.signature.to_dict()
        if self.cc:
            d["cc"] = self.cc
        if self.routing is not None:
            d["routing"] = self.routing
        return d

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict) -> "ATPMessage":
        """Deserialize from dict.

        Reads "from"/"to" keys. Raises MessageFormatError on missing required fields.
        """
        required_fields = ["from", "to", "timestamp", "nonce", "type", "payload"]
        for field_name in required_fields:
            if field_name not in data:
                raise MessageFormatError(
                    ATPErrorCode.INVALID_MESSAGE_FORMAT,
                    f"Missing required field: {field_name!r}",
                )

        signature = None
        if "signature" in data and data["signature"] is not None:
            signature = SignatureEnvelope.from_dict(data["signature"])

        return cls(
            from_id=data["from"],
            to_id=data["to"],
            timestamp=data["timestamp"],
            nonce=data["nonce"],
            type=data["type"],
            payload=data["payload"],
            signature=signature,
            cc=data.get("cc", []),
            routing=data.get("routing"),
        )

    @classmethod
    def from_json(cls, json_str: str) -> "ATPMessage":
        """Deserialize from JSON string."""
        return cls.from_dict(json.loads(json_str))

    def signable_dict(self) -> dict:
        """Same as to_dict() but without the 'signature' key."""
        d = self.to_dict()
        d.pop("signature", None)
        return d
