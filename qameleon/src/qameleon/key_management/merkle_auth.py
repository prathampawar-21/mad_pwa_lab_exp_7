"""Merkle tree authentication for public key verification."""

import hashlib
from dataclasses import dataclass
from typing import Optional


@dataclass
class MerkleProof:
    """Merkle inclusion proof."""
    leaf_index: int
    leaf_hash: bytes
    siblings: list[bytes]
    root: bytes


class MerkleKeyAuthenticator:
    """Builds Merkle trees over public keys for authenticity verification."""

    @staticmethod
    def _hash_leaf(data: bytes) -> bytes:
        return hashlib.sha3_256(b"\x00" + data).digest()

    @staticmethod
    def _hash_node(left: bytes, right: bytes) -> bytes:
        return hashlib.sha3_256(b"\x01" + left + right).digest()

    @classmethod
    def build_tree(cls, public_keys: list[bytes]) -> list[list[bytes]]:
        """Build Merkle tree from list of public keys.
        
        Returns list of levels, level[0] = leaves, level[-1] = [root].
        """
        if not public_keys:
            return [[hashlib.sha3_256(b"").digest()]]

        leaves = [cls._hash_leaf(pk) for pk in public_keys]
        # Pad to power of 2
        n = 1
        while n < len(leaves):
            n <<= 1
        while len(leaves) < n:
            leaves.append(leaves[-1])

        levels = [leaves]
        current = leaves
        while len(current) > 1:
            next_level = []
            for i in range(0, len(current), 2):
                next_level.append(cls._hash_node(current[i], current[i + 1]))
            levels.append(next_level)
            current = next_level

        return levels

    @classmethod
    def get_root(cls, public_keys: list[bytes]) -> bytes:
        """Get Merkle root for a list of public keys."""
        tree = cls.build_tree(public_keys)
        return tree[-1][0]

    @classmethod
    def get_proof(cls, public_keys: list[bytes], index: int) -> MerkleProof:
        """Get inclusion proof for key at index."""
        tree = cls.build_tree(public_keys)
        leaf_hash = cls._hash_leaf(public_keys[index])
        siblings = []
        idx = index
        for level in tree[:-1]:
            sibling_idx = idx ^ 1
            if sibling_idx < len(level):
                siblings.append(level[sibling_idx])
            else:
                siblings.append(level[idx])
            idx >>= 1
        return MerkleProof(
            leaf_index=index,
            leaf_hash=leaf_hash,
            siblings=siblings,
            root=tree[-1][0],
        )

    @classmethod
    def verify_proof(cls, proof: MerkleProof) -> bool:
        """Verify a Merkle inclusion proof."""
        current = proof.leaf_hash
        idx = proof.leaf_index
        for sibling in proof.siblings:
            if idx % 2 == 0:
                current = cls._hash_node(current, sibling)
            else:
                current = cls._hash_node(sibling, current)
            idx >>= 1
        return current == proof.root
