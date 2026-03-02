"""Hash-chained audit logger for key management operations."""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class AuditEventType(Enum):
    """Types of auditable events."""
    KEY_GENERATED = "KEY_GENERATED"
    KEY_STORED = "KEY_STORED"
    KEY_RETRIEVED = "KEY_RETRIEVED"
    KEY_ROTATED = "KEY_ROTATED"
    KEY_EXPIRED = "KEY_EXPIRED"
    KEY_DESTROYED = "KEY_DESTROYED"
    KEY_BACKED_UP = "KEY_BACKED_UP"
    KEY_RECOVERED = "KEY_RECOVERED"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    AUTH_FAILURE = "AUTH_FAILURE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    CROSS_DOMAIN_REQUEST = "CROSS_DOMAIN_REQUEST"


@dataclass
class AuditEntry:
    """A single audit log entry."""
    sequence: int
    event_type: AuditEventType
    key_id: Optional[str]
    actor: str
    details: dict
    timestamp: float
    entry_hash: bytes = field(default_factory=bytes)
    previous_hash: bytes = field(default_factory=bytes)


class AuditLogger:
    """Append-only hash-chained audit log."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []
        self._previous_hash = b"\x00" * 32

    def _compute_hash(self, entry: AuditEntry) -> bytes:
        data = (
            f"{entry.sequence}|{entry.event_type.value}|{entry.key_id}|"
            f"{entry.actor}|{entry.details}|{entry.timestamp}"
        ).encode()
        return hashlib.sha3_256(data + entry.previous_hash).digest()

    def log(
        self,
        event_type: AuditEventType,
        actor: str,
        key_id: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditEntry:
        """Log an audit event."""
        entry = AuditEntry(
            sequence=len(self._entries),
            event_type=event_type,
            key_id=key_id,
            actor=actor,
            details=details or {},
            timestamp=time.time(),
            previous_hash=self._previous_hash,
        )
        entry.entry_hash = self._compute_hash(entry)
        self._entries.append(entry)
        self._previous_hash = entry.entry_hash
        return entry

    def get_entries(
        self,
        event_type: Optional[AuditEventType] = None,
        key_id: Optional[str] = None,
    ) -> list[AuditEntry]:
        """Get audit entries, optionally filtered."""
        entries = self._entries
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if key_id:
            entries = [e for e in entries if e.key_id == key_id]
        return list(entries)

    def verify_chain(self) -> bool:
        """Verify the integrity of the hash chain."""
        prev_hash = b"\x00" * 32
        for entry in self._entries:
            if entry.previous_hash != prev_hash:
                return False
            expected_hash = self._compute_hash(entry)
            if entry.entry_hash != expected_hash:
                return False
            prev_hash = entry.entry_hash
        return True
