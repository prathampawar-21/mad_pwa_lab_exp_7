"""Adaptive rekey manager with configurable triggers."""

import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class RekeyTrigger:
    """Configuration for rekey triggers."""
    threat_threshold: float = 0.7
    max_age_seconds: float = 3600.0
    max_messages: int = 10_000
    max_bytes: int = 100 * 1024 * 1024  # 100 MB


@dataclass
class RekeyState:
    """Current session state for rekey decisions."""
    created_at: float
    last_rekey_at: float
    messages_sent: int
    bytes_sent: int
    current_threat_score: float


class AdaptiveRekeyManager:
    """Manages adaptive rekeying based on threat level and usage."""

    def __init__(self, trigger: Optional[RekeyTrigger] = None) -> None:
        self._trigger = trigger or RekeyTrigger()
        self._state: Optional[RekeyState] = None

    def initialize(self) -> None:
        """Initialize tracking state."""
        now = time.time()
        self._state = RekeyState(
            created_at=now,
            last_rekey_at=now,
            messages_sent=0,
            bytes_sent=0,
            current_threat_score=0.0,
        )

    def record_message(self, byte_count: int) -> None:
        """Record a sent message."""
        if self._state:
            self._state.messages_sent += 1
            self._state.bytes_sent += byte_count

    def update_threat_score(self, score: float) -> None:
        """Update the current threat score."""
        if self._state:
            self._state.current_threat_score = score

    def check_rekey_needed(self) -> tuple[bool, str]:
        """Check if rekeying is needed.
        
        Returns:
            (needs_rekey, reason)
        """
        if self._state is None:
            return False, "not initialized"

        now = time.time()
        age = now - self._state.last_rekey_at

        if self._state.current_threat_score >= self._trigger.threat_threshold:
            return True, f"threat score {self._state.current_threat_score:.2f} exceeds threshold"

        if age >= self._trigger.max_age_seconds:
            return True, f"session age {age:.0f}s exceeds maximum {self._trigger.max_age_seconds}s"

        if self._state.messages_sent >= self._trigger.max_messages:
            return True, f"message count {self._state.messages_sent} exceeds maximum"

        if self._state.bytes_sent >= self._trigger.max_bytes:
            return True, f"bytes sent {self._state.bytes_sent} exceeds maximum"

        return False, "no rekey needed"

    def perform_rekey(self) -> None:
        """Record that a rekey was performed."""
        if self._state:
            self._state.last_rekey_at = time.time()
            self._state.messages_sent = 0
            self._state.bytes_sent = 0
