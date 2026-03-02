"""Unit tests for Hybrid Authenticator."""
import pytest
from qameleon.crypto_primitives.hybrid_auth import HybridAuthenticator


@pytest.mark.unit
class TestHybridAuth:
    def test_keygen(self):
        auth = HybridAuthenticator(65)
        kp = auth.keygen()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)

    def test_sign_verify(self):
        auth = HybridAuthenticator(65)
        kp = auth.keygen()
        msg = b"test message"
        sig = auth.sign(kp.secret_key, msg)
        assert auth.verify(kp.public_key, msg, sig)

    def test_verify_wrong_key(self):
        auth = HybridAuthenticator(65)
        kp1 = auth.keygen()
        kp2 = auth.keygen()
        sig = auth.sign(kp1.secret_key, b"msg")
        with pytest.raises(Exception):
            auth.verify(kp2.public_key, b"msg", sig)
