"""Integration test: end-to-end encryption."""
import pytest
from qameleon.crypto_primitives.ml_kem import MLKEM
from qameleon.crypto_primitives.key_combiner import KeyCombiner
from qameleon.crypto_primitives.symmetric import SymmetricCipher
import os


@pytest.mark.integration
class TestE2EEncryption:
    @pytest.mark.parametrize("level", [512, 768, 1024])
    def test_kem_encrypt_decrypt(self, level):
        kem = MLKEM(level)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        ss = kem.decaps(kp.secret_key, result.ciphertext)
        assert len(ss) == 32

    def test_full_pipeline(self):
        kem = MLKEM(768)
        kp = kem.keygen()
        result = kem.encaps(kp.public_key)
        ss_enc = result.shared_secret
        ss_dec = kem.decaps(kp.secret_key, result.ciphertext)

        # Derive session key
        nonce_a = os.urandom(32)
        nonce_b = os.urandom(32)
        master = KeyCombiner.combine(ss_enc[:16], ss_enc[16:], nonce_a, nonce_b)
        enc_key = KeyCombiner.derive_session_key(master, "encryption")

        # Encrypt/decrypt
        plaintext = b"classified data"
        payload = SymmetricCipher.encrypt(enc_key, plaintext, b"aad")
        recovered = SymmetricCipher.decrypt(enc_key, payload)
        assert recovered == plaintext
