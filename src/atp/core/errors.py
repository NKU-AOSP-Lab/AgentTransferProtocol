"""ATP error types and error codes."""

from enum import Enum
from dataclasses import dataclass


class ATPErrorCode(Enum):
    ATS_VALIDATION_FAILED = "550 5.7.26"
    ATS_TEMP_ERROR = "451 4.7.26"
    ATS_SYNTAX_ERROR = "550 5.7.27"
    ATK_SIGNATURE_FAILED = "550 5.7.28"
    ATK_KEY_NOT_FOUND = "550 5.7.29"
    INVALID_MESSAGE_FORMAT = "400"
    REPLAY_DETECTED = "400"
    RATE_LIMITED = "429"
    SERVER_ERROR = "500"
    DELIVERY_FAILED = "550 5.1.1"


class ATPError(Exception):
    """Base exception for all ATP errors."""

    def __init__(self, code: ATPErrorCode, message: str, details: dict | None = None):
        self.code = code
        self.message = message
        self.details = details
        super().__init__(f"[{code.value}] {message}")


class ATSError(ATPError):
    """Error related to ATS (Agent Transfer Security) validation."""
    ...


class ATKError(ATPError):
    """Error related to ATK (Agent Transfer Keys) operations."""
    ...


class DiscoveryError(ATPError):
    """Error during agent or endpoint discovery."""
    ...


class MessageFormatError(ATPError):
    """Error due to invalid message format."""
    ...


class ReplayError(ATPError):
    """Error when a replay attack is detected."""
    ...


class DeliveryError(ATPError):
    """Error during message delivery."""
    ...


class StorageError(ATPError):
    """Error related to storage operations."""
    ...
