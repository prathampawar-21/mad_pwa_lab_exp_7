"""Unit tests for Hybrid KEM."""
import pytest
from qameleon.crypto_primitives.hybrid_kem import HybridKEM


@pytest.mark.unit
class TestHybridKEM:
    def test_keygen(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)

    def test_encaps_decaps(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        ss = kem.decaps(kp.secret_key, result)
        assert isinstance(ss, bytes)
        assert len(ss) == 32

    def test_shared_secret_determinism(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        ss1 = kem.decaps(kp.secret_key, result)
        ss2 = kem.decaps(kp.secret_key, result)
        assert ss1 == ss2

    def test_key_destroy(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        kp.destroy()
        assert kp.secret_key == b"\x00" * len(kp.secret_key)
