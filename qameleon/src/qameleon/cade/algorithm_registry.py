"""Algorithm registry with profiles for all supported algorithms."""

from dataclasses import dataclass


@dataclass
class AlgorithmProfile:
    """Performance and security profile for an algorithm."""
    name: str
    nist_level: int
    public_key_bytes: int
    secret_key_bytes: int
    ciphertext_bytes: int    # For KEM; signature_bytes for DSA
    shared_secret_bytes: int  # For KEM; 0 for DSA
    keygen_cycles: int
    operation_cycles: int    # encaps/sign cycles
    memory_kb: int
    category: str            # "KEM" or "SIG"


class AlgorithmRegistry:
    """Registry of all supported cryptographic algorithms."""

    _ALGORITHMS: dict[str, AlgorithmProfile] = {
        "ML-KEM-512": AlgorithmProfile(
            name="ML-KEM-512", nist_level=1,
            public_key_bytes=800, secret_key_bytes=1632,
            ciphertext_bytes=768, shared_secret_bytes=32,
            keygen_cycles=400_000, operation_cycles=500_000,
            memory_kb=32, category="KEM",
        ),
        "ML-KEM-768": AlgorithmProfile(
            name="ML-KEM-768", nist_level=3,
            public_key_bytes=1184, secret_key_bytes=2400,
            ciphertext_bytes=1088, shared_secret_bytes=32,
            keygen_cycles=600_000, operation_cycles=750_000,
            memory_kb=48, category="KEM",
        ),
        "ML-KEM-1024": AlgorithmProfile(
            name="ML-KEM-1024", nist_level=5,
            public_key_bytes=1568, secret_key_bytes=3168,
            ciphertext_bytes=1568, shared_secret_bytes=32,
            keygen_cycles=900_000, operation_cycles=1_100_000,
            memory_kb=64, category="KEM",
        ),
        "ML-DSA-44": AlgorithmProfile(
            name="ML-DSA-44", nist_level=2,
            public_key_bytes=1312, secret_key_bytes=2528,
            ciphertext_bytes=2420, shared_secret_bytes=0,
            keygen_cycles=500_000, operation_cycles=2_000_000,
            memory_kb=48, category="SIG",
        ),
        "ML-DSA-65": AlgorithmProfile(
            name="ML-DSA-65", nist_level=3,
            public_key_bytes=1952, secret_key_bytes=4000,
            ciphertext_bytes=3293, shared_secret_bytes=0,
            keygen_cycles=750_000, operation_cycles=3_000_000,
            memory_kb=72, category="SIG",
        ),
        "ML-DSA-87": AlgorithmProfile(
            name="ML-DSA-87", nist_level=5,
            public_key_bytes=2592, secret_key_bytes=4864,
            ciphertext_bytes=4595, shared_secret_bytes=0,
            keygen_cycles=1_100_000, operation_cycles=4_500_000,
            memory_kb=96, category="SIG",
        ),
    }

    @classmethod
    def get(cls, name: str) -> AlgorithmProfile:
        """Get algorithm profile by name."""
        if name not in cls._ALGORITHMS:
            raise KeyError(f"Unknown algorithm: {name}")
        return cls._ALGORITHMS[name]

    @classmethod
    def list_kem(cls) -> list[str]:
        return [k for k, v in cls._ALGORITHMS.items() if v.category == "KEM"]

    @classmethod
    def list_sig(cls) -> list[str]:
        return [k for k, v in cls._ALGORITHMS.items() if v.category == "SIG"]

    @classmethod
    def all_names(cls) -> list[str]:
        return list(cls._ALGORITHMS.keys())
