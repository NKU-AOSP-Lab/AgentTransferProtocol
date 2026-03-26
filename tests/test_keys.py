"""Tests for atp.storage.keys."""

import base64
from pathlib import Path

import pytest

from atp.core.errors import StorageError
from atp.storage.keys import KeyPairInfo, KeyStorage


class TestKeyStorage:
    def test_generate_creates_files(self, tmp_path: Path) -> None:
        """generate() should create .key and .pub files."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")

        info = ks.generate("default")

        assert info.selector == "default"
        assert info.private_key_path.exists()
        assert info.public_key_path.exists()
        assert info.private_key_path.name == "default.key"
        assert info.public_key_path.name == "default.pub"
        assert info.created_at > 0

    def test_load_private_key_after_generate(self, tmp_path: Path) -> None:
        """load_private_key() should return an Ed25519PrivateKey after generation."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")
        ks.generate("default")

        priv = ks.load_private_key("default")

        # Verify it can sign (basic sanity check)
        sig = priv.sign(b"test data")
        assert len(sig) == 64  # Ed25519 signatures are 64 bytes

    def test_load_public_key_after_generate(self, tmp_path: Path) -> None:
        """load_public_key() should return an Ed25519PublicKey after generation."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")
        ks.generate("default")

        pub = ks.load_public_key("default")

        # Verify it can verify a signature
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        assert len(raw) == 32

    def test_load_private_key_missing_raises(self, tmp_path: Path) -> None:
        """load_private_key() should raise StorageError if key file missing."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")

        with pytest.raises(StorageError):
            ks.load_private_key("nonexistent")

    def test_load_public_key_missing_raises(self, tmp_path: Path) -> None:
        """load_public_key() should raise StorageError if key file missing."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")

        with pytest.raises(StorageError):
            ks.load_public_key("nonexistent")

    def test_get_public_key_b64(self, tmp_path: Path) -> None:
        """get_public_key_b64() should return valid base64 decoding to 32 bytes."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")
        ks.generate("default")

        b64 = ks.get_public_key_b64("default")

        raw = base64.b64decode(b64)
        assert len(raw) == 32

    def test_list_keys(self, tmp_path: Path) -> None:
        """list_keys() should return all generated keys."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")
        ks.generate("default")
        ks.generate("backup")

        keys = ks.list_keys()

        selectors = {k.selector for k in keys}
        assert selectors == {"default", "backup"}
        for k in keys:
            assert isinstance(k, KeyPairInfo)
            assert k.created_at > 0

    def test_rotate_creates_new_key_keeps_old(self, tmp_path: Path) -> None:
        """rotate() should create a new key pair; old key should still exist."""
        ks = KeyStorage(keys_dir=tmp_path / "keys")
        ks.generate("old")

        new_info = ks.rotate("old", "new")

        assert new_info.selector == "new"
        assert new_info.private_key_path.exists()
        assert new_info.public_key_path.exists()

        # Old key still exists
        old_priv = ks.load_private_key("old")
        assert old_priv is not None

        # Both appear in list
        selectors = {k.selector for k in ks.list_keys()}
        assert selectors == {"old", "new"}
