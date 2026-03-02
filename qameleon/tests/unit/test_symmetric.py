"""Unit tests for symmetric encryption."""
import pytest
from qameleon.crypto_primitives.symmetric import SymmetricCipher


@pytest.mark.unit
class TestSymmetricCipher:
    def test_generate_key(self):
        key = SymmetricCipher.generate_key()
        assert len(key) == 32

    def test_encrypt_decrypt(self):
        key = SymmetricCipher.generate_key()
        plaintext = b"secret data"
        payload = SymmetricCipher.encrypt(key, plaintext)
        recovered = SymmetricCipher.decrypt(key, payload)
        assert recovered == plaintext

    def test_encrypt_with_aad(self):
        key = SymmetricCipher.generate_key()
        plaintext = b"data"
        aad = b"metadata"
        payload = SymmetricCipher.encrypt(key, plaintext, aad)
        recovered = SymmetricCipher.decrypt(key, payload)
        assert recovered == plaintext

    def test_wrong_key_fails(self):
        key1 = SymmetricCipher.generate_key()
        key2 = SymmetricCipher.generate_key()
        payload = SymmetricCipher.encrypt(key1, b"data")
        with pytest.raises(Exception):
            SymmetricCipher.decrypt(key2, payload)

    def test_nonce_is_random(self):
        key = SymmetricCipher.generate_key()
        p1 = SymmetricCipher.encrypt(key, b"data")
        p2 = SymmetricCipher.encrypt(key, b"data")
        assert p1.nonce != p2.nonce
