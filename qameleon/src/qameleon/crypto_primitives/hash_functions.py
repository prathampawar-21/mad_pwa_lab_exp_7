"""Hash functions wrapping hashlib: SHA3-256, SHA3-512, SHAKE-128, SHAKE-256."""

import hashlib
from enum import Enum


class HashAlgorithm(Enum):
    """Supported hash algorithms."""
    SHA3_256 = "sha3_256"
    SHA3_512 = "sha3_512"
    SHAKE_128 = "shake_128"
    SHAKE_256 = "shake_256"


class HashEngine:
    """Hash function engine with multiple algorithm support."""

    @staticmethod
    def sha3_256(data: bytes) -> bytes:
        """Compute SHA3-256 digest."""
        return hashlib.sha3_256(data).digest()

    @staticmethod
    def sha3_512(data: bytes) -> bytes:
        """Compute SHA3-512 digest."""
        return hashlib.sha3_512(data).digest()

    @staticmethod
    def shake_128(data: bytes, length: int = 32) -> bytes:
        """Compute SHAKE-128 variable-length output."""
        shake = hashlib.shake_128()
        shake.update(data)
        return shake.digest(length)

    @staticmethod
    def shake_256(data: bytes, length: int = 32) -> bytes:
        """Compute SHAKE-256 variable-length output."""
        shake = hashlib.shake_256()
        shake.update(data)
        return shake.digest(length)

    @classmethod
    def hash(cls, algorithm: HashAlgorithm, data: bytes, length: int = 32) -> bytes:
        """Hash data with the specified algorithm."""
        if algorithm == HashAlgorithm.SHA3_256:
            return cls.sha3_256(data)
        elif algorithm == HashAlgorithm.SHA3_512:
            return cls.sha3_512(data)
        elif algorithm == HashAlgorithm.SHAKE_128:
            return cls.shake_128(data, length)
        elif algorithm == HashAlgorithm.SHAKE_256:
            return cls.shake_256(data, length)
        else:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
