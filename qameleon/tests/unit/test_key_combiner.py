"""Unit tests for key combiner."""
import pytest
from qameleon.crypto_primitives.key_combiner import KeyCombiner


@pytest.mark.unit
class TestKeyCombiner:
    def test_combine_produces_64_bytes(self):
        result = KeyCombiner.combine(
            classical_ss=b"a" * 32,
            pq_ss=b"b" * 32,
            nonce_a=b"c" * 32,
            nonce_b=b"d" * 32,
        )
        assert len(result) == 64

    def test_combine_deterministic(self):
        r1 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32)
        r2 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32)
        assert r1 == r2

    def test_classification_bound_into_key(self):
        r0 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32, classification_level=0)
        r1 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32, classification_level=3)
        assert r0 != r1

    def test_derive_session_key(self):
        master = b"m" * 64
        key = KeyCombiner.derive_session_key(master, "encryption", 32)
        assert len(key) == 32

    def test_different_purposes_different_keys(self):
        master = b"m" * 64
        k1 = KeyCombiner.derive_session_key(master, "encryption")
        k2 = KeyCombiner.derive_session_key(master, "authentication")
        assert k1 != k2
