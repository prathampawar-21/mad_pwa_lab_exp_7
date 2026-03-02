"""ML-DSA wrapper with key pair management."""

from dataclasses import dataclass

from qameleon.crypto_primitives.dilithium_core import (
    DilithiumParams, dilithium_keygen, dilithium_sign, dilithium_verify,
)
from qameleon.exceptions import (
    KeyGenerationError, SignatureError, UnsupportedAlgorithmError, VerificationError,
)


@dataclass
class MLDSAKeyPair:
    """ML-DSA key pair with zeroization support."""
    public_key: bytes
    secret_key: bytes
    security_level: int

    def destroy(self) -> None:
        """Zeroize secret key material."""
        if self.secret_key:
            sk_len = len(self.secret_key)
            self.secret_key = b"\x00" * sk_len

    def __del__(self) -> None:
        self.destroy()


class MLDSA:
    """ML-DSA (FIPS 204) digital signature algorithm."""

    _PARAMS = {
        44: DilithiumParams.level_44(),
        65: DilithiumParams.level_65(),
        87: DilithiumParams.level_87(),
    }

    def __init__(self, security_level: int = 65) -> None:
        if security_level not in self._PARAMS:
            raise UnsupportedAlgorithmError(
                f"ML-DSA security level {security_level} not supported. "
                f"Choose from {list(self._PARAMS.keys())}"
            )
        self.security_level = security_level
        self._params = self._PARAMS[security_level]

    def keygen(self) -> MLDSAKeyPair:
        """Generate a new ML-DSA key pair."""
        try:
            pk, sk = dilithium_keygen(self._params)
            return MLDSAKeyPair(
                public_key=pk,
                secret_key=sk,
                security_level=self.security_level,
            )
        except Exception as e:
            raise KeyGenerationError(f"ML-DSA key generation failed: {e}") from e

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign a message."""
        try:
            return dilithium_sign(self._params, secret_key, message)
        except Exception as e:
            raise SignatureError(f"ML-DSA signing failed: {e}") from e

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature."""
        try:
            return dilithium_verify(self._params, public_key, message, signature)
        except Exception as e:
            raise VerificationError(f"ML-DSA verification failed: {e}") from e
