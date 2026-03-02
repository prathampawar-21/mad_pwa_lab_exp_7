"""Security test: forward secrecy."""
import pytest
from qameleon.crypto_primitives.hybrid_kem import HybridKEM


@pytest.mark.security
class TestForwardSecrecy:
    def test_ephemeral_keys_unique(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        r1 = kem.encaps(kp.public_key)
        r2 = kem.encaps(kp.public_key)
        # Each encapsulation should produce different ciphertexts
        assert r1.ciphertext != r2.ciphertext

    def test_key_zeroization(self):
        kem = HybridKEM(768)
        kp = kem.keygen()
        original_len = len(kp.secret_key)
        kp.destroy()
        assert kp.secret_key == b"\x00" * original_len

    def test_different_sessions_different_keys(self):
        kem = HybridKEM(768)
        kp1 = kem.keygen()
        kp2 = kem.keygen()
        r1 = kem.encaps(kp1.public_key)
        r2 = kem.encaps(kp2.public_key)
        assert r1.shared_secret != r2.shared_secret
