"""ATP key storage — manages Ed25519 key pairs in ~/.atp/keys/."""

import base64
import json
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

from atp.core.errors import ATPErrorCode, StorageError


@dataclass
class KeyPairInfo:
    selector: str
    private_key_path: Path
    public_key_path: Path
    created_at: int


class KeyStorage:
    """Manages Ed25519 key pairs in ~/.atp/keys/."""

    def __init__(self, keys_dir: Path):
        self._keys_dir = keys_dir
        self._keys_dir.mkdir(parents=True, exist_ok=True)
        self._keyring_path = self._keys_dir / "keyring.json"

    def _load_keyring(self) -> dict:
        if self._keyring_path.exists():
            return json.loads(self._keyring_path.read_text(encoding="utf-8"))
        return {"keys": {}}

    def _save_keyring(self, keyring: dict) -> None:
        self._keyring_path.write_text(
            json.dumps(keyring, indent=2), encoding="utf-8"
        )

    def generate(self, selector: str = "default") -> KeyPairInfo:
        """Generate Ed25519 key pair.

        Save as {selector}.key (PEM PKCS8, no encryption) and
        {selector}.pub (PEM SubjectPublicKeyInfo). Update keyring.json.
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_path = self._keys_dir / f"{selector}.key"
        pub_path = self._keys_dir / f"{selector}.pub"

        priv_pem = private_key.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
        pub_pem = public_key.public_bytes(
            Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
        )

        priv_path.write_bytes(priv_pem)
        pub_path.write_bytes(pub_pem)

        created_at = int(time.time())

        keyring = self._load_keyring()
        keyring["keys"][selector] = {
            "private_key": f"{selector}.key",
            "public_key": f"{selector}.pub",
            "created_at": created_at,
        }
        self._save_keyring(keyring)

        return KeyPairInfo(
            selector=selector,
            private_key_path=priv_path,
            public_key_path=pub_path,
            created_at=created_at,
        )

    def load_private_key(self, selector: str = "default") -> Ed25519PrivateKey:
        """Load from {selector}.key. Raise StorageError if not found."""
        priv_path = self._keys_dir / f"{selector}.key"
        if not priv_path.exists():
            raise StorageError(
                ATPErrorCode.SERVER_ERROR,
                f"Private key not found for selector '{selector}'",
            )
        data = priv_path.read_bytes()
        key = load_pem_private_key(data, password=None)
        assert isinstance(key, Ed25519PrivateKey)
        return key

    def load_public_key(self, selector: str = "default") -> Ed25519PublicKey:
        """Load from {selector}.pub. Raise StorageError if not found."""
        pub_path = self._keys_dir / f"{selector}.pub"
        if not pub_path.exists():
            raise StorageError(
                ATPErrorCode.SERVER_ERROR,
                f"Public key not found for selector '{selector}'",
            )
        data = pub_path.read_bytes()
        key = load_pem_public_key(data)
        assert isinstance(key, Ed25519PublicKey)
        return key

    def get_public_key_b64(self, selector: str = "default") -> str:
        """Return base64-encoded raw public key bytes (32 bytes for Ed25519).

        Suitable for DNS ATK record publication.
        """
        pub_key = self.load_public_key(selector)
        raw = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def list_keys(self) -> list[KeyPairInfo]:
        """List all keys from keyring.json."""
        keyring = self._load_keyring()
        result: list[KeyPairInfo] = []
        for selector, info in keyring.get("keys", {}).items():
            result.append(
                KeyPairInfo(
                    selector=selector,
                    private_key_path=self._keys_dir / info["private_key"],
                    public_key_path=self._keys_dir / info["public_key"],
                    created_at=info["created_at"],
                )
            )
        return result

    def rotate(self, old_selector: str, new_selector: str) -> KeyPairInfo:
        """Generate new key with new_selector. Does NOT delete old key."""
        return self.generate(new_selector)
