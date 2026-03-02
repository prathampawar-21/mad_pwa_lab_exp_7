"""Node discovery using beacon messages."""

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DiscoveryBeacon:
    """Beacon broadcast for node discovery."""
    node_id: str
    public_key_hash: str
    classification_level: int
    supported_kem: list[str]
    supported_sig: list[str]
    timestamp: float = field(default_factory=time.time)
    address: str = ""
    port: int = 0


class NodeDiscovery:
    """Tracks discovered neighbors via beacon messages."""

    BEACON_EXPIRY = 300.0  # 5 minutes

    def __init__(self, local_node_id: str) -> None:
        self.local_node_id = local_node_id
        self._neighbors: dict[str, DiscoveryBeacon] = {}

    def process_beacon(self, beacon: DiscoveryBeacon) -> bool:
        """Process a received beacon. Returns True if new neighbor."""
        if beacon.node_id == self.local_node_id:
            return False

        is_new = beacon.node_id not in self._neighbors
        self._neighbors[beacon.node_id] = beacon
        return is_new

    def get_neighbors(self) -> list[DiscoveryBeacon]:
        """Get list of active neighbors."""
        now = time.time()
        active = {
            k: v for k, v in self._neighbors.items()
            if now - v.timestamp < self.BEACON_EXPIRY
        }
        self._neighbors = active
        return list(active.values())

    def get_neighbor(self, node_id: str) -> Optional[DiscoveryBeacon]:
        """Get a specific neighbor's beacon."""
        return self._neighbors.get(node_id)

    def remove_neighbor(self, node_id: str) -> None:
        """Remove a neighbor."""
        self._neighbors.pop(node_id, None)
