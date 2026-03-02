"""Hybrid KEM combining ML-KEM and X25519."""

import hashlib
import os
from dataclasses import dataclass

from qameleon.crypto_primitives.classical import ClassicalKeyExchange
from qameleon.crypto_primitives.ml_kem import MLKEM, MLKEMEncapsResult
from qameleon.exceptions import DecapsulationError, EncapsulationError, KeyGenerationError


@dataclass
class HybridKEMKeyPair:
    """Hybrid KEM key pair combining ML-KEM and X25519."""
    public_key: bytes       # ML-KEM pk || X25519 pk
    secret_key: bytes       # ML-KEM sk || X25519 sk
    security_level: int

    def destroy(self) -> None:
        sk_len = len(self.secret_key)
        self.secret_key = b"\x00" * sk_len

    def __del__(self) -> None:
        self.destroy()


@dataclass
class HybridEncapsResult:
    """Result of hybrid KEM encapsulation."""
    ciphertext: bytes       # ML-KEM ct || X25519 ephemeral pk
    shared_secret: bytes    # Combined shared secret (32 bytes)


class HybridKEM:
    """Hybrid KEM: ML-KEM + X25519 with combined shared secret."""

    def __init__(self, security_level: int = 768) -> None:
        self.security_level = security_level
        self._mlkem = MLKEM(security_level)

    def keygen(self) -> HybridKEMKeyPair:
        """Generate hybrid KEM key pair."""
        try:
            mlkem_kp = self._mlkem.keygen()
            classical = ClassicalKeyExchange.generate()

            public_key = mlkem_kp.public_key + classical.public_key
            secret_key = mlkem_kp.secret_key + classical.private_key
            return HybridKEMKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                security_level=self.security_level,
            )
        except Exception as e:
            raise KeyGenerationError(f"Hybrid KEM key generation failed: {e}") from e

    def encaps(self, public_key: bytes) -> HybridEncapsResult:
        """Encapsulate to both ML-KEM and X25519 recipients."""
        try:
            # Split public key
            mlkem_pk_size = len(public_key) - 32
            mlkem_pk = public_key[:mlkem_pk_size]
            classical_pk = public_key[mlkem_pk_size:]

            # ML-KEM encapsulation
            mlkem_result = self._mlkem.encaps(mlkem_pk)

            # X25519 encapsulation (ephemeral key exchange)
            ephemeral = ClassicalKeyExchange.generate()
            classical_ss = ephemeral.shared_secret(classical_pk)

            # Combine shared secrets using HKDF
            combined_ss = self._combine(mlkem_result.shared_secret, classical_ss)
            ciphertext = mlkem_result.ciphertext + ephemeral.public_key

            return HybridEncapsResult(ciphertext=ciphertext, shared_secret=combined_ss)
        except Exception as e:
            raise EncapsulationError(f"Hybrid KEM encapsulation failed: {e}") from e

    def decaps(self, secret_key: bytes, encaps_result: "HybridEncapsResult") -> bytes:
        """Decapsulate to recover combined shared secret."""
        try:
            ciphertext = encaps_result.ciphertext
            # Determine sizes based on security level
            mlkem_ct_sizes = {512: 768, 768: 1088, 1024: 1568}
            mlkem_ct_size = mlkem_ct_sizes.get(self.security_level, 1088)

            # Split ciphertext
            mlkem_ct = ciphertext[:mlkem_ct_size]
            ephemeral_pk = ciphertext[mlkem_ct_size:]

            # Split secret key
            mlkem_sk_sizes = {
                512: 2 * 384 + (2 * 384 + 32) + 32 + 32,
                768: 3 * 384 + (3 * 384 + 32) + 32 + 32,
                1024: 4 * 384 + (4 * 384 + 32) + 32 + 32,
            }
            mlkem_sk_size = mlkem_sk_sizes.get(self.security_level, 2400)
            mlkem_sk = secret_key[:mlkem_sk_size]
            classical_sk = secret_key[mlkem_sk_size:]

            # ML-KEM decapsulation
            mlkem_ss = self._mlkem.decaps(mlkem_sk, mlkem_ct)

            # X25519 decapsulation
            classical = ClassicalKeyExchange(private_key=classical_sk, public_key=b"")
            classical_ss = classical.shared_secret(ephemeral_pk)

            # Combine
            return self._combine(mlkem_ss, classical_ss)
        except Exception as e:
            raise DecapsulationError(f"Hybrid KEM decapsulation failed: {e}") from e

    @staticmethod
    def _combine(pq_ss: bytes, classical_ss: bytes) -> bytes:
        """Combine post-quantum and classical shared secrets using HKDF."""
        combined_ikm = pq_ss + classical_ss
        prk = hashlib.sha3_256(b"QAMELEON-HYBRID-KEM" + combined_ikm).digest()
        return hashlib.sha3_256(prk + b"combined-shared-secret").digest()
