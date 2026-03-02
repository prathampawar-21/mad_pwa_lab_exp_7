"""QHP (QAMELEON Handshake Protocol) implementation."""

import hashlib
import os
import time
from dataclasses import dataclass, field
from typing import Optional

from qameleon.crypto_primitives.hybrid_auth import HybridAuthenticator, HybridSigningKeyPair
from qameleon.crypto_primitives.hybrid_kem import HybridEncapsResult, HybridKEM, HybridKEMKeyPair
from qameleon.crypto_primitives.key_combiner import KeyCombiner
from qameleon.exceptions import HandshakeError, ReplayDetectedError
from qameleon.protocol.messages import HandshakeMessage, MessageType, serialize_message
from qameleon.protocol.state_machine import HandshakeState, HandshakeStateMachine


@dataclass
class HandshakeContext:
    """Context maintained during QHP handshake."""
    node_id: str
    kem_keypair: Optional[HybridKEMKeyPair] = None
    signing_keypair: Optional[HybridSigningKeyPair] = None
    peer_kem_public_key: Optional[bytes] = None
    peer_signing_public_key: Optional[bytes] = None
    local_nonce: bytes = field(default_factory=lambda: os.urandom(32))
    peer_nonce: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    master_key: Optional[bytes] = None
    classification_level: int = 0
    state_machine: HandshakeStateMachine = field(default_factory=HandshakeStateMachine)
    seen_nonces: set[bytes] = field(default_factory=set)


class QHPHandshake:
    """Implements the 4-phase QAMELEON Handshake Protocol."""

    def __init__(self, node_id: str, classification_level: int = 0) -> None:
        self.node_id = node_id
        self.classification_level = classification_level
        self._kem = HybridKEM()
        self._auth = HybridAuthenticator()

    def create_context(self) -> HandshakeContext:
        """Create a new handshake context with fresh keys."""
        ctx = HandshakeContext(
            node_id=self.node_id,
            classification_level=self.classification_level,
        )
        ctx.kem_keypair = self._kem.keygen()
        ctx.signing_keypair = self._auth.keygen()
        return ctx

    def create_hello(self, ctx: HandshakeContext) -> bytes:
        """Create HELLO message (initiator -> responder)."""
        ctx.state_machine.transition(HandshakeState.HELLO_SENT)
        msg = HandshakeMessage(
            msg_type=MessageType.HELLO,
            sender_id=self.node_id,
            nonce=ctx.local_nonce,
            payload={
                "kem_public_key": ctx.kem_keypair.public_key.hex(),
                "signing_public_key": ctx.signing_keypair.public_key.hex(),
                "classification_level": self.classification_level,
                "supported_kem": ["ML-KEM-768", "ML-KEM-1024"],
                "supported_sig": ["ML-DSA-65", "ML-DSA-87"],
            },
        )
        msg_bytes = serialize_message(msg)
        # Sign the message
        sig = self._auth.sign(ctx.signing_keypair.secret_key, msg_bytes)
        msg.signature = sig
        return serialize_message(msg)

    def process_hello(
        self, ctx: HandshakeContext, hello_bytes: bytes
    ) -> tuple[bytes, HandshakeContext]:
        """Process HELLO and create HELLO_RESPONSE (responder side)."""
        from qameleon.protocol.messages import parse_message
        msg = parse_message(hello_bytes)

        if msg.msg_type != MessageType.HELLO:
            raise HandshakeError(f"Expected HELLO, got {msg.msg_type}")

        # Check nonce replay
        if msg.nonce in ctx.seen_nonces:
            raise ReplayDetectedError("Replay detected in HELLO")
        ctx.seen_nonces.add(msg.nonce)

        ctx.peer_kem_public_key = bytes.fromhex(msg.payload["kem_public_key"])
        ctx.peer_signing_public_key = bytes.fromhex(msg.payload["signing_public_key"])
        ctx.peer_nonce = msg.nonce
        ctx.state_machine.transition(HandshakeState.HELLO_RECEIVED)
        ctx.state_machine.transition(HandshakeState.NEGOTIATED)

        response = HandshakeMessage(
            msg_type=MessageType.HELLO_RESPONSE,
            sender_id=self.node_id,
            nonce=ctx.local_nonce,
            payload={
                "kem_public_key": ctx.kem_keypair.public_key.hex(),
                "signing_public_key": ctx.signing_keypair.public_key.hex(),
                "classification_level": self.classification_level,
                "selected_kem": "ML-KEM-768",
                "selected_sig": "ML-DSA-65",
            },
        )
        resp_bytes = serialize_message(response)
        sig = self._auth.sign(ctx.signing_keypair.secret_key, resp_bytes)
        response.signature = sig
        return serialize_message(response), ctx

    def process_hello_response(
        self, ctx: HandshakeContext, response_bytes: bytes
    ) -> HandshakeContext:
        """Process HELLO_RESPONSE (initiator side)."""
        from qameleon.protocol.messages import parse_message
        msg = parse_message(response_bytes)

        if msg.msg_type != MessageType.HELLO_RESPONSE:
            raise HandshakeError(f"Expected HELLO_RESPONSE, got {msg.msg_type}")

        if msg.nonce in ctx.seen_nonces:
            raise ReplayDetectedError("Replay detected in HELLO_RESPONSE")
        ctx.seen_nonces.add(msg.nonce)

        ctx.peer_kem_public_key = bytes.fromhex(msg.payload["kem_public_key"])
        ctx.peer_signing_public_key = bytes.fromhex(msg.payload["signing_public_key"])
        ctx.peer_nonce = msg.nonce
        ctx.state_machine.transition(HandshakeState.NEGOTIATED)
        return ctx

    def create_key_init(self, ctx: HandshakeContext) -> bytes:
        """Create KEY_INIT message (initiator encapsulates to responder)."""
        encaps_result = self._kem.encaps(ctx.peer_kem_public_key)
        ctx.shared_secret = encaps_result.shared_secret

        ctx.state_machine.transition(HandshakeState.KEY_INIT_SENT)

        msg = HandshakeMessage(
            msg_type=MessageType.KEY_INIT,
            sender_id=self.node_id,
            nonce=os.urandom(32),
            payload={
                "ciphertext": encaps_result.ciphertext.hex(),
                "initiator_nonce": ctx.local_nonce.hex(),
            },
        )
        msg_bytes = serialize_message(msg)
        sig = self._auth.sign(ctx.signing_keypair.secret_key, msg_bytes)
        msg.signature = sig
        return serialize_message(msg)

    def process_key_init(
        self, ctx: HandshakeContext, key_init_bytes: bytes
    ) -> tuple[bytes, bytes]:
        """Process KEY_INIT and create KEY_RESPONSE (responder)."""
        from qameleon.protocol.messages import parse_message
        msg = parse_message(key_init_bytes)

        if msg.msg_type != MessageType.KEY_INIT:
            raise HandshakeError(f"Expected KEY_INIT, got {msg.msg_type}")

        ciphertext = bytes.fromhex(msg.payload["ciphertext"])
        initiator_nonce = bytes.fromhex(msg.payload["initiator_nonce"])

        # Decapsulate
        encaps_result = HybridEncapsResult(
            ciphertext=ciphertext,
            shared_secret=b"",  # Will be computed by decaps
        )
        shared_secret = self._kem.decaps(ctx.kem_keypair.secret_key, encaps_result)
        ctx.shared_secret = shared_secret

        # Derive master key
        ctx.master_key = KeyCombiner.combine(
            classical_ss=shared_secret[:32],
            pq_ss=shared_secret[32:] if len(shared_secret) > 32 else shared_secret,
            nonce_a=initiator_nonce,
            nonce_b=ctx.local_nonce,
            classification_level=self.classification_level,
        )
        ctx.state_machine.transition(HandshakeState.KEY_RESP_SENT)

        resp_nonce = os.urandom(32)
        response = HandshakeMessage(
            msg_type=MessageType.KEY_RESPONSE,
            sender_id=self.node_id,
            nonce=resp_nonce,
            payload={
                "responder_nonce": ctx.local_nonce.hex(),
                "confirmation": hashlib.sha3_256(ctx.master_key + b"CONFIRM").hexdigest(),
            },
        )
        resp_bytes = serialize_message(response)
        sig = self._auth.sign(ctx.signing_keypair.secret_key, resp_bytes)
        response.signature = sig
        serialized = serialize_message(response)
        ctx.state_machine.transition(HandshakeState.ESTABLISHED)
        return serialized, ctx.master_key

    def finalize(self, ctx: HandshakeContext, key_response_bytes: bytes) -> bytes:
        """Finalize handshake on initiator side, derive master key."""
        from qameleon.protocol.messages import parse_message
        msg = parse_message(key_response_bytes)

        responder_nonce = bytes.fromhex(msg.payload["responder_nonce"])
        ctx.master_key = KeyCombiner.combine(
            classical_ss=ctx.shared_secret[:32],
            pq_ss=ctx.shared_secret[32:] if len(ctx.shared_secret) > 32 else ctx.shared_secret,
            nonce_a=ctx.local_nonce,
            nonce_b=responder_nonce,
            classification_level=self.classification_level,
        )
        ctx.state_machine.transition(HandshakeState.ESTABLISHED)
        return ctx.master_key
