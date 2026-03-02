"""Mesh node integrating all QAMELEON layers."""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from qameleon.crypto_primitives.hybrid_auth import HybridAuthenticator
from qameleon.crypto_primitives.hybrid_kem import HybridKEM
from qameleon.key_management.key_store import KeyStore
from qameleon.mesh_network.mesh_router import MeshRouter
from qameleon.mesh_network.node_discovery import DiscoveryBeacon, NodeDiscovery
from qameleon.protocol.handshake import HandshakeContext, QHPHandshake
from qameleon.protocol.session import SecureSession
from qameleon.threat_intel.unified_threat_score import UnifiedThreatScorer


@dataclass
class MeshNodeStatus:
    """Current status of a mesh node."""
    node_id: str
    classification_level: int
    active_sessions: int
    known_neighbors: int
    threat_score: float
    uptime_seconds: float
    started_at: float = field(default_factory=time.time)


class MeshNode:
    """Full-featured mesh network node integrating all QAMELEON layers."""

    def __init__(
        self,
        node_id: str,
        classification_level: int = 0,
    ) -> None:
        self.node_id = node_id
        self.classification_level = classification_level
        self._started_at = time.time()

        # Layers
        self._handshake = QHPHandshake(node_id, classification_level)
        self._kem = HybridKEM()
        self._auth = HybridAuthenticator()
        self._key_store = KeyStore()
        self._router = MeshRouter(node_id)
        self._discovery = NodeDiscovery(node_id)
        self._threat_scorer = UnifiedThreatScorer()

        # State
        self._sessions: dict[str, SecureSession] = {}
        self._pending_handshakes: dict[str, HandshakeContext] = {}
        self._local_ctx: Optional[HandshakeContext] = None

    def initialize(self) -> None:
        """Initialize the node with fresh keys."""
        self._local_ctx = self._handshake.create_context()

    def create_beacon(self) -> DiscoveryBeacon:
        """Create a discovery beacon for broadcasting."""
        pk_hash = ""
        if self._local_ctx and self._local_ctx.signing_keypair:
            pk_hash = hashlib.sha3_256(
                self._local_ctx.signing_keypair.public_key
            ).hexdigest()[:16]

        return DiscoveryBeacon(
            node_id=self.node_id,
            public_key_hash=pk_hash,
            classification_level=self.classification_level,
            supported_kem=["ML-KEM-768", "ML-KEM-1024"],
            supported_sig=["ML-DSA-65", "ML-DSA-87"],
        )

    def process_beacon(self, beacon: DiscoveryBeacon) -> bool:
        """Process a received discovery beacon."""
        is_new = self._discovery.process_beacon(beacon)
        if is_new:
            self._router.add_route(
                destination=beacon.node_id,
                next_hop=beacon.node_id,
                hop_count=1,
                classification_level=beacon.classification_level,
            )
        return is_new

    def initiate_handshake(self, peer_node_id: str) -> bytes:
        """Initiate QHP handshake with a peer node."""
        ctx = self._handshake.create_context()
        self._pending_handshakes[peer_node_id] = ctx
        return self._handshake.create_hello(ctx)

    def respond_to_hello(self, hello_bytes: bytes, peer_node_id: str) -> bytes:
        """Respond to a HELLO message (responder side)."""
        ctx = self._handshake.create_context()
        response, ctx = self._handshake.process_hello(ctx, hello_bytes)
        self._pending_handshakes[peer_node_id] = ctx
        return response

    def process_hello_response_and_send_key_init(
        self, response_bytes: bytes, peer_node_id: str
    ) -> bytes:
        """Process HELLO_RESPONSE and send KEY_INIT (initiator side)."""
        ctx = self._pending_handshakes[peer_node_id]
        ctx = self._handshake.process_hello_response(ctx, response_bytes)
        return self._handshake.create_key_init(ctx)

    def process_key_init_and_respond(
        self, key_init_bytes: bytes, peer_node_id: str
    ) -> bytes:
        """Process KEY_INIT and send KEY_RESPONSE (responder side)."""
        ctx = self._pending_handshakes[peer_node_id]
        response_bytes, master_key = self._handshake.process_key_init(ctx, key_init_bytes)
        session = SecureSession(master_key, f"{self.node_id}-{peer_node_id}")
        self._sessions[peer_node_id] = session
        return response_bytes

    def finalize_initiator_session(
        self, key_response_bytes: bytes, peer_node_id: str
    ) -> SecureSession:
        """Finalize session on initiator side."""
        ctx = self._pending_handshakes[peer_node_id]
        master_key = self._handshake.finalize(ctx, key_response_bytes)
        session = SecureSession(master_key, f"{self.node_id}-{peer_node_id}")
        self._sessions[peer_node_id] = session
        del self._pending_handshakes[peer_node_id]
        return session

    def finalize_responder_session(self, peer_node_id: str) -> Optional[SecureSession]:
        """Get the established session for responder."""
        return self._sessions.get(peer_node_id)

    def get_status(self) -> MeshNodeStatus:
        """Get current node status."""
        threat_snapshot = self._threat_scorer.compute()
        return MeshNodeStatus(
            node_id=self.node_id,
            classification_level=self.classification_level,
            active_sessions=len(self._sessions),
            known_neighbors=len(self._discovery.get_neighbors()),
            threat_score=threat_snapshot.unified_score,
            uptime_seconds=time.time() - self._started_at,
        )

    def shutdown(self) -> None:
        """Shutdown the node, zeroizing keys."""
        for session in self._sessions.values():
            session.destroy()
        self._sessions.clear()
        if self._local_ctx and self._local_ctx.kem_keypair:
            self._local_ctx.kem_keypair.destroy()
        if self._local_ctx and self._local_ctx.signing_keypair:
            self._local_ctx.signing_keypair.destroy()
