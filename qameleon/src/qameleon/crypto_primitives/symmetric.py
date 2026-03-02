"""AES-256-GCM symmetric encryption."""

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass


@dataclass
class EncryptedPayload:
    """Container for AES-256-GCM encrypted data."""
    nonce: bytes        # 12-byte random nonce
    ciphertext: bytes   # Encrypted data + GCM tag
    aad: bytes          # Additional authenticated data
    algorithm: str = "AES-256-GCM"


class SymmetricCipher:
    """AES-256-GCM encryption/decryption."""

    KEY_SIZE = 32   # 256 bits
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)
    TAG_SIZE = 16   # 128 bits

    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 256-bit key."""
        return os.urandom(SymmetricCipher.KEY_SIZE)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> EncryptedPayload:
        """Encrypt plaintext with AES-256-GCM.

        Uses Python's cryptography library if available, otherwise falls back
        to a pure-Python implementation.

        .. warning::
            The pure-Python fallback uses SHA-256-based keystream generation
            (not actual AES-CTR) and a simplified HMAC-based tag (not true
            GHASH). It does **not** provide the same security guarantees as
            real AES-256-GCM and must not be used in production. Install the
            ``cryptography`` package to use the secure implementation.
        """
        if len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricCipher.KEY_SIZE} bytes")

        nonce = os.urandom(SymmetricCipher.NONCE_SIZE)

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, aad or None)
            return EncryptedPayload(nonce=nonce, ciphertext=ciphertext_with_tag, aad=aad)
        except ImportError:
            # Pure Python fallback using counter mode + HMAC
            ciphertext = SymmetricCipher._aes_ctr_encrypt(key, nonce, plaintext)
            tag = SymmetricCipher._compute_ghash(key, nonce, ciphertext, aad)
            return EncryptedPayload(nonce=nonce, ciphertext=ciphertext + tag, aad=aad)

    @staticmethod
    def decrypt(key: bytes, payload: EncryptedPayload) -> bytes:
        """Decrypt AES-256-GCM encrypted payload."""
        if len(key) != SymmetricCipher.KEY_SIZE:
            raise ValueError(f"Key must be {SymmetricCipher.KEY_SIZE} bytes")

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(payload.nonce, payload.ciphertext, payload.aad or None)
        except ImportError:
            ciphertext = payload.ciphertext[:-SymmetricCipher.TAG_SIZE]
            tag = payload.ciphertext[-SymmetricCipher.TAG_SIZE:]
            expected_tag = SymmetricCipher._compute_ghash(key, payload.nonce, ciphertext, payload.aad)
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError("Authentication tag mismatch - decryption failed")
            return SymmetricCipher._aes_ctr_encrypt(key, payload.nonce, ciphertext)

    @staticmethod
    def _aes_ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
        """SHA-256-based keystream XOR (pure-Python fallback only).

        .. warning::
            This is **not** true AES-CTR. It uses SHA-256 for keystream
            generation and is vulnerable to distinguishing attacks. Only
            used when the ``cryptography`` package is unavailable.
        """
        result = bytearray(len(data))
        block_size = 16
        for i in range(0, len(data), block_size):
            counter = i // block_size
            keystream = hashlib.sha256(
                key + nonce + counter.to_bytes(4, 'big')
            ).digest()
            chunk = data[i:i + block_size]
            for j in range(len(chunk)):
                result[i + j] = chunk[j] ^ keystream[j]
        return bytes(result)

    @staticmethod
    def _compute_ghash(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        """Compute authentication tag (simplified GHASH)."""
        mac_key = hashlib.sha256(b"GHASH-KEY" + key + nonce).digest()
        h = hmac.new(mac_key, aad + ciphertext, hashlib.sha256)
        return h.digest()[:16]
