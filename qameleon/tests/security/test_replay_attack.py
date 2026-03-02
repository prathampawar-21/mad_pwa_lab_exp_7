"""Security test: replay attack resistance."""
import pytest
import os
from qameleon.protocol.messages import HandshakeMessage, MessageType, serialize_message
from qameleon.protocol.handshake import QHPHandshake
from qameleon.exceptions import ReplayDetectedError


@pytest.mark.security
class TestReplayAttack:
    def test_nonce_replay_detected(self):
        hs = QHPHandshake("alice")
        ctx = hs.create_context()
        nonce = os.urandom(32)
        ctx.seen_nonces.add(nonce)

        msg = HandshakeMessage(
            msg_type=MessageType.HELLO,
            sender_id="attacker",
            nonce=nonce,
            payload={
                "kem_public_key": "aa" * 1184,
                "signing_public_key": "bb" * 1984,
                "classification_level": 0,
                "supported_kem": ["ML-KEM-768"],
                "supported_sig": ["ML-DSA-65"],
            },
        )
        msg_bytes = serialize_message(msg)
        with pytest.raises(ReplayDetectedError):
            hs.process_hello(ctx, msg_bytes)
