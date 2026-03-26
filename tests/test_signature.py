"""Tests for atp.core.signature."""

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atp.core.message import ATPMessage
from atp.core.signature import Signer, Verifier


def _make_key_pair():
    """Generate a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


class TestSignAndVerify:
    """Test Signer and Verifier together."""

    def test_sign_and_verify_passes(self):
        private_key, public_key = _make_key_pair()
        signer = Signer(private_key, "default", "example.com")

        msg = ATPMessage.create("alice@example.com", "bob@other.com", {"text": "hi"})
        signed_msg = signer.sign(msg)

        assert signed_msg.signature is not None
        assert signed_msg.signature.key_id == "default.atk._atp.example.com"
        assert signed_msg.signature.algorithm == "ed25519"

        result = Verifier.verify(signed_msg, public_key)
        assert result.passed is True
        assert result.error_code is None

    def test_tamper_payload_fails_verification(self):
        private_key, public_key = _make_key_pair()
        signer = Signer(private_key, "default", "example.com")

        msg = ATPMessage.create("alice@example.com", "bob@other.com", {"text": "hi"})
        signed_msg = signer.sign(msg)

        # Tamper with the payload
        signed_msg.payload["text"] = "tampered"

        result = Verifier.verify(signed_msg, public_key)
        assert result.passed is False
        assert result.error_code == "550 5.7.28"

    def test_tamper_to_field_fails_verification(self):
        private_key, public_key = _make_key_pair()
        signer = Signer(private_key, "default", "example.com")

        msg = ATPMessage.create("alice@example.com", "bob@other.com", {"text": "hi"})
        signed_msg = signer.sign(msg)

        # Tamper with the "to" field
        signed_msg.to_id = "eve@evil.com"

        result = Verifier.verify(signed_msg, public_key)
        assert result.passed is False
        assert result.error_code == "550 5.7.28"

    def test_wrong_public_key_fails_verification(self):
        private_key, _public_key = _make_key_pair()
        _, wrong_public_key = _make_key_pair()

        signer = Signer(private_key, "default", "example.com")
        msg = ATPMessage.create("alice@example.com", "bob@other.com", {"text": "hi"})
        signed_msg = signer.sign(msg)

        result = Verifier.verify(signed_msg, wrong_public_key)
        assert result.passed is False
        assert result.error_code == "550 5.7.28"

    def test_verify_unsigned_message(self):
        _, public_key = _make_key_pair()
        msg = ATPMessage.create("alice@example.com", "bob@other.com", {"text": "hi"})

        result = Verifier.verify(msg, public_key)
        assert result.passed is False
        assert result.error_code == "550 5.7.28"
        assert "no signature" in result.error_message.lower()
