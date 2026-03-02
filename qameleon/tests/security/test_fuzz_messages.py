"""Security test: fuzz testing of message parsing."""
import pytest
import os
from qameleon.protocol.messages import parse_message
from qameleon.exceptions import InvalidMessageError


@pytest.mark.security
class TestFuzzMessages:
    def test_random_bytes_rejected(self):
        for _ in range(20):
            data = os.urandom(256)
            with pytest.raises((InvalidMessageError, Exception)):
                parse_message(data)

    def test_empty_bytes_rejected(self):
        with pytest.raises((InvalidMessageError, Exception)):
            parse_message(b"")

    def test_truncated_json_rejected(self):
        with pytest.raises((InvalidMessageError, Exception)):
            parse_message(b'{"msg_type": "HELLO"')

    def test_missing_fields_rejected(self):
        with pytest.raises((InvalidMessageError, Exception)):
            parse_message(b'{"msg_type": "HELLO", "sender_id": "x"}')

    def test_invalid_msg_type_rejected(self):
        with pytest.raises((InvalidMessageError, Exception)):
            import json
            data = json.dumps({
                "msg_type": "INVALID",
                "sender_id": "x",
                "nonce": "aa" * 32,
                "payload": {},
                "timestamp": 0,
                "signature": "",
            }).encode()
            parse_message(data)
