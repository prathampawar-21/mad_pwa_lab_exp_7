"""Unit tests for hash functions."""
import pytest
from qameleon.crypto_primitives.hash_functions import HashEngine, HashAlgorithm


@pytest.mark.unit
class TestHashFunctions:
    def test_sha3_256(self):
        h = HashEngine.sha3_256(b"test")
        assert len(h) == 32

    def test_sha3_512(self):
        h = HashEngine.sha3_512(b"test")
        assert len(h) == 64

    def test_shake_128(self):
        h = HashEngine.shake_128(b"test", 64)
        assert len(h) == 64

    def test_shake_256(self):
        h = HashEngine.shake_256(b"test", 48)
        assert len(h) == 48

    def test_deterministic(self):
        h1 = HashEngine.sha3_256(b"data")
        h2 = HashEngine.sha3_256(b"data")
        assert h1 == h2

    def test_different_inputs_different_outputs(self):
        h1 = HashEngine.sha3_256(b"a")
        h2 = HashEngine.sha3_256(b"b")
        assert h1 != h2

    def test_hash_enum(self):
        h = HashEngine.hash(HashAlgorithm.SHA3_256, b"test")
        assert len(h) == 32
