"""ML-KEM wrapper with key pair management."""

import os
from dataclasses import dataclass
from typing import Optional

from qameleon.crypto_primitives.kyber_core import (
    KyberParams, kyber_keygen, kyber_encaps, kyber_decaps,
)
from qameleon.exceptions import (
    DecapsulationError, EncapsulationError, KeyGenerationError, UnsupportedAlgorithmError,
)


@dataclass
class MLKEMKeyPair:
    """ML-KEM key pair with zeroization support."""
    public_key: bytes
    secret_key: bytes
    security_level: int

    def destroy(self) -> None:
        """Zeroize secret key material."""
        if self.secret_key:
            # Overwrite with zeros
            sk_len = len(self.secret_key)
            self.secret_key = b"\x00" * sk_len

    def __del__(self) -> None:
        self.destroy()


@dataclass
class MLKEMEncapsResult:
    """Result of ML-KEM encapsulation."""
    ciphertext: bytes
    shared_secret: bytes


class MLKEM:
    """ML-KEM (FIPS 203) key encapsulation mechanism."""

    _PARAMS = {
        512: KyberParams.level_512(),
        768: KyberParams.level_768(),
        1024: KyberParams.level_1024(),
    }

    _PK_SIZES = {
        512: 2 * 384 + 32,
        768: 3 * 384 + 32,
        1024: 4 * 384 + 32,
    }

    _SK_SIZES = {
        512: 2 * 384 + (2 * 384 + 32) + 32 + 32,
        768: 3 * 384 + (3 * 384 + 32) + 32 + 32,
        1024: 4 * 384 + (4 * 384 + 32) + 32 + 32,
    }

    def __init__(self, security_level: int = 768) -> None:
        if security_level not in self._PARAMS:
            raise UnsupportedAlgorithmError(
                f"ML-KEM security level {security_level} not supported. "
                f"Choose from {list(self._PARAMS.keys())}"
            )
        self.security_level = security_level
        self._params = self._PARAMS[security_level]

    def keygen(self) -> MLKEMKeyPair:
        """Generate a new ML-KEM key pair."""
        try:
            pk, sk = kyber_keygen(self._params)
            return MLKEMKeyPair(
                public_key=pk,
                secret_key=sk,
                security_level=self.security_level,
            )
        except Exception as e:
            raise KeyGenerationError(f"ML-KEM key generation failed: {e}") from e

    def encaps(self, public_key: bytes) -> MLKEMEncapsResult:
        """Encapsulate to produce ciphertext and shared secret."""
        expected_pk_size = self._PK_SIZES[self.security_level]
        if len(public_key) != expected_pk_size:
            raise EncapsulationError(
                f"Invalid public key size: expected {expected_pk_size}, got {len(public_key)}"
            )
        try:
            ciphertext, shared_secret = kyber_encaps(self._params, public_key)
            return MLKEMEncapsResult(ciphertext=ciphertext, shared_secret=shared_secret)
        except Exception as e:
            raise EncapsulationError(f"ML-KEM encapsulation failed: {e}") from e

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate to recover shared secret."""
        try:
            return kyber_decaps(self._params, secret_key, ciphertext)
        except Exception as e:
            raise DecapsulationError(f"ML-KEM decapsulation failed: {e}") from e
