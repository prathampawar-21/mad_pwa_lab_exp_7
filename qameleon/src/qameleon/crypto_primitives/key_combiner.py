"""Key combination using HKDF for session key derivation."""

import hashlib
import hmac
import os


class KeyCombiner:
    """Combines multiple key material sources using HKDF."""

    @staticmethod
    def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
        """HKDF-Extract: PRK = HMAC-SHA3-256(salt, IKM)."""
        if not salt:
            salt = b"\x00" * 32
        return hmac.new(salt, ikm, hashlib.sha3_256).digest()

    @staticmethod
    def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
        """HKDF-Expand: generate `length` bytes from PRK."""
        output = b""
        T = b""
        counter = 1
        while len(output) < length:
            T = hmac.new(prk, T + info + bytes([counter]), hashlib.sha3_256).digest()
            output += T
            counter += 1
        return output[:length]

    @classmethod
    def combine(
        cls,
        classical_ss: bytes,
        pq_ss: bytes,
        nonce_a: bytes,
        nonce_b: bytes,
        classification_level: int = 0,
        algorithm: str = "HYBRID-KEM",
    ) -> bytes:
        """Combine classical and PQ shared secrets into a 64-byte master key.
        
        Classification level is bound into the HKDF info string to prevent
        cross-domain key reuse.
        """
        # IKM = classical_ss || pq_ss
        ikm = classical_ss + pq_ss
        # Salt = nonce_a || nonce_b
        salt = nonce_a + nonce_b
        # Info binds algorithm, classification, and context
        info = (
            b"QAMELEON-MASTER-KEY-v1"
            + b"|alg=" + algorithm.encode()
            + b"|class=" + str(classification_level).encode()
        )
        prk = cls._hkdf_extract(salt, ikm)
        return cls._hkdf_expand(prk, info, 64)

    @classmethod
    def derive_session_key(cls, master_key: bytes, purpose: str, length: int = 32) -> bytes:
        """Derive a session key from master key for a specific purpose."""
        info = b"QAMELEON-SESSION-KEY-v1|purpose=" + purpose.encode()
        prk = cls._hkdf_extract(b"", master_key)
        return cls._hkdf_expand(prk, info, length)
