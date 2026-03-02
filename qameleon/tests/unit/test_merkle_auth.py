"""Unit tests for Merkle authentication."""
import pytest
from qameleon.key_management.merkle_auth import MerkleKeyAuthenticator


@pytest.mark.unit
class TestMerkleAuth:
    def test_root_reproducible(self):
        keys = [b"pk1", b"pk2", b"pk3", b"pk4"]
        r1 = MerkleKeyAuthenticator.get_root(keys)
        r2 = MerkleKeyAuthenticator.get_root(keys)
        assert r1 == r2

    def test_proof_verify(self):
        keys = [b"pk1", b"pk2", b"pk3", b"pk4"]
        proof = MerkleKeyAuthenticator.get_proof(keys, 1)
        assert MerkleKeyAuthenticator.verify_proof(proof)

    def test_tampered_proof_fails(self):
        keys = [b"pk1", b"pk2", b"pk3", b"pk4"]
        proof = MerkleKeyAuthenticator.get_proof(keys, 0)
        proof.leaf_hash = b"\x00" * 32
        assert not MerkleKeyAuthenticator.verify_proof(proof)

    def test_single_key(self):
        keys = [b"only_key"]
        root = MerkleKeyAuthenticator.get_root(keys)
        assert isinstance(root, bytes)
