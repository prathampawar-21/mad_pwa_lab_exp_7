"""Message authentication for QHP wire messages."""

import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Optional

from qameleon.crypto_primitives.hybrid_auth import HybridAuthenticator, HybridSigningKeyPair
from qameleon.exceptions import InvalidMessageError, ReplayDetectedError


@dataclass
class AuthenticatedMessage:
    """A message with integrity and authentication."""
    content_hash: bytes
    timestamp: float
    nonce: bytes
    signature: bytes
    sender_id: str


class MessageAuthenticator:
    """Signs and verifies QHP protocol messages."""

    FRESHNESS_WINDOW = 300.0  # 5 minutes

    def __init__(self, signing_key: HybridSigningKeyPair, sender_id: str) -> None:
        self._key = signing_key
        self._sender_id = sender_id
        self._auth = HybridAuthenticator()
        self._seen_nonces: set[bytes] = set()

    def sign(self, message_bytes: bytes, nonce: bytes) -> AuthenticatedMessage:
        """Sign a message."""
        content_hash = hashlib.sha3_256(message_bytes).digest()
        timestamp = time.time()
        ts_bytes = struct.pack(">d", timestamp)
        to_sign = content_hash + ts_bytes + nonce

        signature = self._auth.sign(self._key.secret_key, to_sign)
        return AuthenticatedMessage(
            content_hash=content_hash,
            timestamp=timestamp,
            nonce=nonce,
            signature=signature,
            sender_id=self._sender_id,
        )

    def verify(
        self,
        message_bytes: bytes,
        auth: AuthenticatedMessage,
        public_key: bytes,
    ) -> bool:
        """Verify a message's authenticity and freshness."""
        # Check replay
        if auth.nonce in self._seen_nonces:
            raise ReplayDetectedError(f"Replay detected: nonce {auth.nonce.hex()}")
        self._seen_nonces.add(auth.nonce)

        # Check freshness
        age = time.time() - auth.timestamp
        if abs(age) > self.FRESHNESS_WINDOW:
            raise InvalidMessageError(f"Message too old: {age:.0f}s")

        # Verify hash
        expected_hash = hashlib.sha3_256(message_bytes).digest()
        if expected_hash != auth.content_hash:
            raise InvalidMessageError("Message hash mismatch")

        # Verify signature
        ts_bytes = struct.pack(">d", auth.timestamp)
        to_verify = auth.content_hash + ts_bytes + auth.nonce
        return self._auth.verify(public_key, to_verify, auth.signature)
