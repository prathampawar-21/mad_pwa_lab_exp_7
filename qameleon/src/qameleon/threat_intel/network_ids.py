"""Network intrusion detection system."""

import time
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class AlertSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class NetworkEvent:
    """A network event to analyze."""
    message_id: str
    source_ip: str
    event_type: str
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class NetworkAlert:
    """A network security alert."""
    alert_type: str
    severity: AlertSeverity
    source_ip: str
    details: str
    timestamp: float


class NetworkIDS:
    """Analyzes network events for intrusion patterns."""

    REPLAY_WINDOW = 300.0       # 5 minutes
    MAX_AUTH_FAILURES = 5       # Per minute
    MAX_CONNECTIONS_PER_MIN = 50

    def __init__(self) -> None:
        self._seen_message_ids: dict[str, float] = {}
        self._auth_failures: dict[str, list[float]] = defaultdict(list)
        self._connection_rates: dict[str, list[float]] = defaultdict(list)

    def analyze(self, event: NetworkEvent) -> Optional[NetworkAlert]:
        """Analyze an event and return an alert if detected."""
        now = time.time()

        # Check replay
        if event.event_type in ("KEY_INIT", "KEY_RESPONSE", "HELLO", "DATA"):
            if event.message_id in self._seen_message_ids:
                old_ts = self._seen_message_ids[event.message_id]
                if now - old_ts < self.REPLAY_WINDOW:
                    return NetworkAlert(
                        alert_type="REPLAY_ATTACK",
                        severity=AlertSeverity.HIGH,
                        source_ip=event.source_ip,
                        details=f"Duplicate message_id: {event.message_id}",
                        timestamp=now,
                    )
            self._seen_message_ids[event.message_id] = now

        # Check auth brute force
        if event.event_type == "AUTH_FAILURE":
            self._auth_failures[event.source_ip].append(now)
            # Prune old failures
            cutoff = now - 60.0
            self._auth_failures[event.source_ip] = [
                t for t in self._auth_failures[event.source_ip] if t > cutoff
            ]
            if len(self._auth_failures[event.source_ip]) >= self.MAX_AUTH_FAILURES:
                return NetworkAlert(
                    alert_type="BRUTE_FORCE",
                    severity=AlertSeverity.HIGH,
                    source_ip=event.source_ip,
                    details=f"Auth failures: {len(self._auth_failures[event.source_ip])}/min",
                    timestamp=now,
                )

        # Check connection rate
        self._connection_rates[event.source_ip].append(now)
        cutoff = now - 60.0
        self._connection_rates[event.source_ip] = [
            t for t in self._connection_rates[event.source_ip] if t > cutoff
        ]
        if len(self._connection_rates[event.source_ip]) > self.MAX_CONNECTIONS_PER_MIN:
            return NetworkAlert(
                alert_type="RATE_LIMIT",
                severity=AlertSeverity.MEDIUM,
                source_ip=event.source_ip,
                details=f"Connection rate: {len(self._connection_rates[event.source_ip])}/min",
                timestamp=now,
            )

        return None
