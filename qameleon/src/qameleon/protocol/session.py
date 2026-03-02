"""Secure session for post-handshake communication."""

import time
from dataclasses import dataclass, field
from typing import Optional

from qameleon.crypto_primitives.symmetric import EncryptedPayload, SymmetricCipher
from qameleon.crypto_primitives.key_combiner import KeyCombiner
from qameleon.exceptions import SessionExpiredError


@dataclass
class SessionStats:
    """Session usage statistics."""
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    created_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None


class SecureSession:
    """Encrypted session using derived keys from QHP handshake."""

    def __init__(
        self,
        master_key: bytes,
        session_id: str,
        max_lifetime: float = 3600.0,
    ) -> None:
        self._master_key = master_key
        self.session_id = session_id
        self._cipher = SymmetricCipher()
        self._destroyed = False
        self.stats = SessionStats(
            created_at=time.time(),
            expires_at=time.time() + max_lifetime,
        )
        # Derive session encryption key
        self._enc_key = KeyCombiner.derive_session_key(master_key, "encryption", 32)
        self._mac_key = KeyCombiner.derive_session_key(master_key, "authentication", 32)

    def _check_valid(self) -> None:
        if self._destroyed:
            raise SessionExpiredError("Session has been destroyed")
        if self.stats.expires_at and time.time() > self.stats.expires_at:
            raise SessionExpiredError("Session has expired")

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> EncryptedPayload:
        """Encrypt data in this session."""
        self._check_valid()
        payload = SymmetricCipher.encrypt(self._enc_key, plaintext, aad)
        self.stats.messages_sent += 1
        self.stats.bytes_sent += len(plaintext)
        return payload

    def decrypt(self, payload: EncryptedPayload) -> bytes:
        """Decrypt data in this session."""
        self._check_valid()
        plaintext = SymmetricCipher.decrypt(self._enc_key, payload)
        self.stats.messages_received += 1
        self.stats.bytes_received += len(plaintext)
        return plaintext

    def update_key(self, new_master_key: bytes) -> None:
        """Update session keys (rekey)."""
        self._check_valid()
        self._master_key = new_master_key
        self._enc_key = KeyCombiner.derive_session_key(new_master_key, "encryption", 32)
        self._mac_key = KeyCombiner.derive_session_key(new_master_key, "authentication", 32)

    def get_stats(self) -> SessionStats:
        """Get session statistics."""
        return self.stats

    def destroy(self) -> None:
        """Zeroize session keys."""
        self._enc_key = b"\x00" * 32
        self._mac_key = b"\x00" * 32
        self._master_key = b"\x00" * len(self._master_key)
        self._destroyed = True
