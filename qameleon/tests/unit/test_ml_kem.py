"""Unit tests for ML-KEM."""
import pytest
from qameleon.crypto_primitives.ml_kem import MLKEM, MLKEMKeyPair, MLKEMEncapsResult
from qameleon.exceptions import UnsupportedAlgorithmError, EncapsulationError


@pytest.mark.unit
class TestMLKEM:
    def test_keygen_768(self):
        kem = MLKEM(768)
        kp = kem.keygen()
        assert isinstance(kp.public_key, bytes)
        assert isinstance(kp.secret_key, bytes)
        assert len(kp.public_key) > 0
        assert kp.security_level == 768

    def test_keygen_512(self):
        kem = MLKEM(512)
        kp = kem.keygen()
        assert kp.security_level == 512

    def test_keygen_1024(self):
        kem = MLKEM(1024)
        kp = kem.keygen()
        assert kp.security_level == 1024

    def test_unsupported_level(self):
        with pytest.raises(UnsupportedAlgorithmError):
            MLKEM(256)

    def test_encaps_decaps_768(self):
        kem = MLKEM(768)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        assert isinstance(result.ciphertext, bytes)
        assert isinstance(result.shared_secret, bytes)
        ss = kem.decaps(kp.secret_key, result.ciphertext)
        assert isinstance(ss, bytes)
        assert len(ss) == 32

    def test_invalid_public_key_size(self):
        kem = MLKEM(768)
        with pytest.raises(EncapsulationError):
            kem.encaps(b"short")

    def test_encaps_result_type(self):
        kem = MLKEM(768)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        assert isinstance(result, MLKEMEncapsResult)

    def test_key_pair_destroy(self):
        kem = MLKEM(768)
        kp = kem.keygen()
        kp.destroy()
        assert kp.secret_key == b"\x00" * len(kp.secret_key)

    def test_different_keys_produce_different_results(self):
        kem = MLKEM(768)
        kp1 = kem.keygen()
        kp2 = kem.keygen()
        r1 = kem.encaps(kp1.public_key)
        r2 = kem.encaps(kp2.public_key)
        assert r1.shared_secret != r2.shared_secret
