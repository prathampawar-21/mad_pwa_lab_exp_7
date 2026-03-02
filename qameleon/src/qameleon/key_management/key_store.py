"""Thread-safe in-memory key store with key lifecycle management."""

import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class KeyState(Enum):
    """Key lifecycle states."""
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    EXPIRED = "EXPIRED"
    DESTROYED = "DESTROYED"


@dataclass
class KeyEntry:
    """A stored key with metadata."""
    key_id: str
    key_material: bytes
    state: KeyState
    algorithm: str
    classification_level: int
    created_at: float
    expires_at: Optional[float]
    rotated_from: Optional[str] = None


class KeyStore:
    """Thread-safe in-memory key store."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._keys: dict[str, KeyEntry] = {}

    def store(
        self,
        key_id: str,
        key_material: bytes,
        algorithm: str,
        classification_level: int = 0,
        expires_in: Optional[float] = None,
    ) -> KeyEntry:
        """Store a key in the store."""
        with self._lock:
            expires_at = time.time() + expires_in if expires_in else None
            entry = KeyEntry(
                key_id=key_id,
                key_material=key_material,
                state=KeyState.ACTIVE,
                algorithm=algorithm,
                classification_level=classification_level,
                created_at=time.time(),
                expires_at=expires_at,
            )
            self._keys[key_id] = entry
            return entry

    def retrieve(self, key_id: str) -> Optional[KeyEntry]:
        """Retrieve a key by ID. Returns None if not found or destroyed."""
        with self._lock:
            entry = self._keys.get(key_id)
            if entry is None or entry.state == KeyState.DESTROYED:
                return None
            # Check expiry
            if entry.expires_at and time.time() > entry.expires_at:
                entry.state = KeyState.EXPIRED
            return entry

    def rotate(self, old_key_id: str, new_key_id: str, new_key_material: bytes) -> KeyEntry:
        """Rotate a key, marking the old one as ROTATED."""
        with self._lock:
            old_entry = self._keys.get(old_key_id)
            if old_entry:
                old_entry.state = KeyState.ROTATED
            algorithm = old_entry.algorithm if old_entry else "UNKNOWN"
            classification_level = old_entry.classification_level if old_entry else 0
            new_entry = KeyEntry(
                key_id=new_key_id,
                key_material=new_key_material,
                state=KeyState.ACTIVE,
                algorithm=algorithm,
                classification_level=classification_level,
                created_at=time.time(),
                expires_at=None,
                rotated_from=old_key_id,
            )
            self._keys[new_key_id] = new_entry
            return new_entry

    def expire(self, key_id: str) -> None:
        """Mark a key as expired."""
        with self._lock:
            if key_id in self._keys:
                self._keys[key_id].state = KeyState.EXPIRED

    def destroy(self, key_id: str) -> None:
        """Destroy a key by zeroizing its material."""
        with self._lock:
            if key_id in self._keys:
                entry = self._keys[key_id]
                entry.key_material = b"\x00" * len(entry.key_material)
                entry.state = KeyState.DESTROYED

    def list_keys(self, state_filter: Optional[KeyState] = None) -> list[str]:
        """List key IDs, optionally filtered by state."""
        with self._lock:
            if state_filter is None:
                return list(self._keys.keys())
            return [k for k, v in self._keys.items() if v.state == state_filter]
