"""Unit tests for ML-DSA."""
import pytest
from qameleon.crypto_primitives.ml_dsa import MLDSA, MLDSAKeyPair
from qameleon.exceptions import UnsupportedAlgorithmError


@pytest.mark.unit
class TestMLDSA:
    def test_keygen_65(self):
        dsa = MLDSA(65)
        kp = dsa.keygen()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)
        assert kp.security_level == 65

    def test_keygen_44(self):
        dsa = MLDSA(44)
        kp = dsa.keygen()
        assert kp.security_level == 44

    def test_keygen_87(self):
        dsa = MLDSA(87)
        kp = dsa.keygen()
        assert kp.security_level == 87

    def test_unsupported_level(self):
        with pytest.raises(UnsupportedAlgorithmError):
            MLDSA(128)

    def test_sign_verify(self):
        dsa = MLDSA(65)
        kp = dsa.keygen()
        msg = b"test message"
        sig = dsa.sign(kp.secret_key, msg)
        assert isinstance(sig, bytes)
        assert dsa.verify(kp.public_key, msg, sig)

    def test_verify_wrong_message(self):
        dsa = MLDSA(65)
        kp = dsa.keygen()
        sig = dsa.sign(kp.secret_key, b"original")
        assert not dsa.verify(kp.public_key, b"tampered", sig)

    def test_key_pair_destroy(self):
        dsa = MLDSA(65)
        kp = dsa.keygen()
        kp.destroy()
        assert kp.secret_key == b"\x00" * len(kp.secret_key)
