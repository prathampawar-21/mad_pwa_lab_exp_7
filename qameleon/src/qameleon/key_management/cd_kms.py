"""Cross-Domain Key Management System."""

import os
import time
from typing import Optional

from qameleon.crypto_primitives.symmetric import SymmetricCipher
from qameleon.key_management.audit_logger import AuditEventType, AuditLogger
from qameleon.key_management.key_store import KeyState, KeyStore
from qameleon.key_management.merkle_auth import MerkleKeyAuthenticator
from qameleon.key_management.threshold_sss import ThresholdSecretSharing


class CrossDomainKMS:
    """Orchestrates key management across classification domains."""

    def __init__(self) -> None:
        self._store = KeyStore()
        self._merkle = MerkleKeyAuthenticator()
        self._sss = ThresholdSecretSharing()
        self._audit = AuditLogger()
        self._public_keys: list[bytes] = []

    def generate_key(
        self,
        key_id: str,
        algorithm: str = "AES-256-GCM",
        classification_level: int = 0,
        actor: str = "system",
    ) -> bytes:
        """Generate and store a new key."""
        key = SymmetricCipher.generate_key()
        self._store.store(key_id, key, algorithm, classification_level)
        self._audit.log(AuditEventType.KEY_GENERATED, actor, key_id, {"algorithm": algorithm})
        return key

    def rotate_key(
        self,
        old_key_id: str,
        new_key_id: str,
        actor: str = "system",
    ) -> bytes:
        """Rotate a key, generating a new one."""
        new_key = SymmetricCipher.generate_key()
        self._store.rotate(old_key_id, new_key_id, new_key)
        self._audit.log(AuditEventType.KEY_ROTATED, actor, new_key_id,
                        {"rotated_from": old_key_id})
        return new_key

    def revoke_key(self, key_id: str, actor: str = "system") -> None:
        """Revoke (destroy) a key."""
        self._store.destroy(key_id)
        self._audit.log(AuditEventType.KEY_DESTROYED, actor, key_id)

    def backup_key(
        self,
        key_id: str,
        k: int = 3,
        n: int = 5,
        actor: str = "system",
    ) -> list:
        """Backup a key using Shamir's Secret Sharing."""
        entry = self._store.retrieve(key_id)
        if entry is None:
            raise ValueError(f"Key {key_id} not found")
        shares = ThresholdSecretSharing.split(entry.key_material, k, n)
        self._audit.log(AuditEventType.KEY_BACKED_UP, actor, key_id, {"k": k, "n": n})
        return shares

    def recover_key(
        self,
        key_id: str,
        shares: list,
        algorithm: str = "AES-256-GCM",
        classification_level: int = 0,
        actor: str = "system",
    ) -> bytes:
        """Recover a key from Shamir shares."""
        key = ThresholdSecretSharing.reconstruct(shares)
        self._store.store(key_id, key, algorithm, classification_level)
        self._audit.log(AuditEventType.KEY_RECOVERED, actor, key_id)
        return key

    def get_audit_log(self) -> list:
        """Get all audit log entries."""
        return self._audit.get_entries()
