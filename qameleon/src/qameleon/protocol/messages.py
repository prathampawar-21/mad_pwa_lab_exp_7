"""QHP message types and serialization."""

import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from qameleon.exceptions import InvalidMessageError


class MessageType(Enum):
    """QHP message types."""
    HELLO = "HELLO"
    HELLO_RESPONSE = "HELLO_RESPONSE"
    KEY_INIT = "KEY_INIT"
    KEY_RESPONSE = "KEY_RESPONSE"
    DATA = "DATA"
    REKEY = "REKEY"
    TERMINATE = "TERMINATE"
    ERROR = "ERROR"


@dataclass
class HandshakeMessage:
    """A QHP protocol message."""
    msg_type: MessageType
    sender_id: str
    nonce: bytes
    payload: dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    signature: bytes = b""

    def to_dict(self) -> dict:
        return {
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "nonce": self.nonce.hex(),
            "payload": self.payload,
            "timestamp": self.timestamp,
            "signature": self.signature.hex(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HandshakeMessage":
        return cls(
            msg_type=MessageType(data["msg_type"]),
            sender_id=data["sender_id"],
            nonce=bytes.fromhex(data["nonce"]),
            payload=data["payload"],
            timestamp=data.get("timestamp", time.time()),
            signature=bytes.fromhex(data.get("signature", "")),
        )


def serialize_message(msg: HandshakeMessage) -> bytes:
    """Serialize a message to bytes."""
    return json.dumps(msg.to_dict()).encode()


def parse_message(data: bytes) -> HandshakeMessage:
    """Parse a message from bytes."""
    try:
        d = json.loads(data.decode())
        return HandshakeMessage.from_dict(d)
    except (json.JSONDecodeError, KeyError, ValueError) as e:
        raise InvalidMessageError(f"Failed to parse message: {e}") from e
