"""Unit tests for classical cryptography."""
import pytest
from qameleon.crypto_primitives.classical import (
    ClassicalKeyExchange, ClassicalSignature,
    x25519_generate, x25519_shared_secret,
    ed25519_generate, ed25519_sign,
)


@pytest.mark.unit
class TestClassical:
    def test_x25519_keygen(self):
        priv, pub = x25519_generate()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_x25519_dh(self):
        priv1, pub1 = x25519_generate()
        priv2, pub2 = x25519_generate()
        ss1 = x25519_shared_secret(priv1, pub2)
        ss2 = x25519_shared_secret(priv2, pub1)
        assert ss1 == ss2
        assert len(ss1) == 32

    def test_ed25519_keygen(self):
        seed, pub = ed25519_generate()
        assert len(seed) == 32
        assert len(pub) == 32

    def test_ed25519_sign(self):
        seed, pub = ed25519_generate()
        sig = ed25519_sign(seed, b"message")
        assert len(sig) == 64

    def test_classical_key_exchange(self):
        kex = ClassicalKeyExchange.generate()
        assert len(kex.private_key) == 32
        assert len(kex.public_key) == 32

    def test_classical_signature(self):
        signer = ClassicalSignature.generate()
        sig = signer.sign(b"test")
        assert isinstance(sig, bytes)
        assert signer.verify(b"test", sig)
