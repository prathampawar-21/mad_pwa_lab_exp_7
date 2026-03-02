"""Unit tests for key store."""
import pytest
from qameleon.key_management.key_store import KeyStore, KeyState


@pytest.mark.unit
class TestKeyStore:
    def test_store_retrieve(self):
        ks = KeyStore()
        ks.store("k1", b"keydata", "AES-256-GCM")
        entry = ks.retrieve("k1")
        assert entry is not None
        assert entry.key_material == b"keydata"
        assert entry.state == KeyState.ACTIVE

    def test_rotate(self):
        ks = KeyStore()
        ks.store("k1", b"old", "AES-256-GCM")
        ks.rotate("k1", "k2", b"new")
        old = ks.retrieve("k1")
        new = ks.retrieve("k2")
        assert old.state == KeyState.ROTATED
        assert new.key_material == b"new"

    def test_destroy(self):
        ks = KeyStore()
        ks.store("k1", b"secret", "AES-256-GCM")
        ks.destroy("k1")
        assert ks.retrieve("k1") is None

    def test_list_keys(self):
        ks = KeyStore()
        ks.store("k1", b"d1", "A")
        ks.store("k2", b"d2", "A")
        keys = ks.list_keys()
        assert "k1" in keys
        assert "k2" in keys
