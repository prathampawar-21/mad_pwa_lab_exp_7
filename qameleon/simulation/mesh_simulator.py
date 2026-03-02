"""Discrete-event mesh network simulator."""

import time
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class SimEvent:
    """A simulation event."""
    time: float
    event_type: str
    source: str
    target: str
    data: dict = field(default_factory=dict)


class MeshSimulator:
    """Discrete-event simulator for QAMELEON mesh networks."""

    def __init__(self, num_nodes: int = 10) -> None:
        self.num_nodes = num_nodes
        self._events: list[SimEvent] = []
        self._time = 0.0
        self._stats: dict[str, int] = {
            "messages_sent": 0,
            "handshakes": 0,
            "rekeys": 0,
            "attacks_detected": 0,
        }

    def schedule(self, delay: float, event_type: str, source: str, target: str, data: dict = None) -> None:
        """Schedule an event."""
        event = SimEvent(
            time=self._time + delay,
            event_type=event_type,
            source=source,
            target=target,
            data=data or {},
        )
        self._events.append(event)
        self._events.sort(key=lambda e: e.time)

    def run(self, duration: float) -> dict:
        """Run the simulation for the given duration."""
        end_time = self._time + duration
        processed = 0

        while self._events and self._events[0].time <= end_time:
            event = self._events.pop(0)
            self._time = event.time
            self._process_event(event)
            processed += 1

        return {
            "duration": duration,
            "events_processed": processed,
            "stats": self._stats.copy(),
        }

    def _process_event(self, event: SimEvent) -> None:
        if event.event_type == "HANDSHAKE":
            self._stats["handshakes"] += 1
        elif event.event_type == "MESSAGE":
            self._stats["messages_sent"] += 1
        elif event.event_type == "REKEY":
            self._stats["rekeys"] += 1
        elif event.event_type == "ATTACK":
            self._stats["attacks_detected"] += 1
