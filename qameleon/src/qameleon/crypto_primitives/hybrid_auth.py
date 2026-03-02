"""Hybrid authenticator combining ML-DSA and Ed25519."""

import hashlib
from dataclasses import dataclass

from qameleon.crypto_primitives.classical import ClassicalSignature
from qameleon.crypto_primitives.ml_dsa import MLDSA
from qameleon.exceptions import KeyGenerationError, SignatureError, VerificationError


@dataclass
class HybridSigningKeyPair:
    """Hybrid signing key pair (ML-DSA + Ed25519)."""
    public_key: bytes       # ML-DSA pk || Ed25519 pk
    secret_key: bytes       # ML-DSA sk || Ed25519 seed
    security_level: int

    def destroy(self) -> None:
        sk_len = len(self.secret_key)
        self.secret_key = b"\x00" * sk_len

    def __del__(self) -> None:
        self.destroy()


@dataclass
class HybridSignature:
    """Hybrid signature (ML-DSA + Ed25519)."""
    pq_signature: bytes
    classical_signature: bytes

    def to_bytes(self) -> bytes:
        pq_len = len(self.pq_signature).to_bytes(4, 'big')
        return pq_len + self.pq_signature + self.classical_signature

    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridSignature":
        if len(data) < 4:
            raise ValueError("Hybrid signature too short")
        pq_len = int.from_bytes(data[:4], 'big')
        if len(data) < 4 + pq_len:
            raise ValueError("Hybrid signature truncated")
        pq_sig = data[4:4 + pq_len]
        classical_sig = data[4 + pq_len:]
        return cls(pq_signature=pq_sig, classical_signature=classical_sig)


class HybridAuthenticator:
    """Hybrid digital signature: ML-DSA + Ed25519."""

    def __init__(self, security_level: int = 65) -> None:
        self.security_level = security_level
        self._mldsa = MLDSA(security_level)

    def keygen(self) -> HybridSigningKeyPair:
        """Generate hybrid signing key pair."""
        try:
            dsa_kp = self._mldsa.keygen()
            classical = ClassicalSignature.generate()

            public_key = dsa_kp.public_key + classical.public_key
            secret_key = dsa_kp.secret_key + classical.seed
            return HybridSigningKeyPair(
                public_key=public_key,
                secret_key=secret_key,
                security_level=self.security_level,
            )
        except Exception as e:
            raise KeyGenerationError(f"Hybrid authenticator key generation failed: {e}") from e

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message with both ML-DSA and Ed25519."""
        try:
            # Split secret key - ML-DSA sk + Ed25519 seed (32 bytes)
            ed25519_seed = secret_key[-32:]
            mldsa_sk = secret_key[:-32]

            pq_sig = self._mldsa.sign(mldsa_sk, message)

            classical = ClassicalSignature(seed=ed25519_seed, public_key=b"")
            classical_sig = classical.sign(message)

            sig = HybridSignature(pq_signature=pq_sig, classical_signature=classical_sig)
            return sig.to_bytes()
        except Exception as e:
            raise SignatureError(f"Hybrid signing failed: {e}") from e

    def verify(self, public_key: bytes, message: bytes, signature_bytes: bytes) -> bool:
        """Verify both ML-DSA and Ed25519 signatures."""
        try:
            sig = HybridSignature.from_bytes(signature_bytes)

            # Split public key - Ed25519 pk is last 32 bytes
            ed25519_pk = public_key[-32:]
            mldsa_pk = public_key[:-32]

            pq_valid = self._mldsa.verify(mldsa_pk, message, sig.pq_signature)

            classical = ClassicalSignature(seed=b"", public_key=ed25519_pk)
            classical_valid = classical.verify(message, sig.classical_signature)

            return pq_valid and classical_valid
        except Exception as e:
            raise VerificationError(f"Hybrid verification failed: {e}") from e
