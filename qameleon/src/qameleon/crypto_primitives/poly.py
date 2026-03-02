"""Kyber polynomial and polynomial vector operations."""

import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional

from qameleon.crypto_primitives.ntt import (
    KYBER_N, KYBER_Q, kyber_ntt, kyber_ntt_inv,
)


@dataclass
class KyberPoly:
    """Polynomial with coefficients in Z_q[x]/(x^256 + 1)."""

    coeffs: list[int] = field(default_factory=lambda: [0] * KYBER_N)

    def __post_init__(self) -> None:
        if len(self.coeffs) != KYBER_N:
            raise ValueError(f"Polynomial must have exactly {KYBER_N} coefficients")

    def add(self, other: "KyberPoly") -> "KyberPoly":
        return KyberPoly([(a + b) % KYBER_Q for a, b in zip(self.coeffs, other.coeffs)])

    def sub(self, other: "KyberPoly") -> "KyberPoly":
        return KyberPoly([(a - b) % KYBER_Q for a, b in zip(self.coeffs, other.coeffs)])

    def ntt(self) -> "KyberPoly":
        return KyberPoly(kyber_ntt(self.coeffs))

    def ntt_inv(self) -> "KyberPoly":
        return KyberPoly(kyber_ntt_inv(self.coeffs))

    def pointwise_mul(self, other: "KyberPoly") -> "KyberPoly":
        return KyberPoly([(a * b) % KYBER_Q for a, b in zip(self.coeffs, other.coeffs)])

    def compress(self, d: int) -> list[int]:
        """Compress coefficients to d bits."""
        result = []
        for c in self.coeffs:
            compressed = ((c * (1 << d) + KYBER_Q // 2) // KYBER_Q) % (1 << d)
            result.append(compressed)
        return result

    @classmethod
    def decompress(cls, compressed: list[int], d: int) -> "KyberPoly":
        """Decompress coefficients from d-bit representation."""
        coeffs = []
        for c in compressed:
            decompressed = (c * KYBER_Q + (1 << (d - 1))) >> d
            coeffs.append(decompressed % KYBER_Q)
        return cls(coeffs)

    def to_bytes(self) -> bytes:
        """Serialize polynomial to bytes (12 bits per coefficient)."""
        result = bytearray()
        for i in range(0, KYBER_N, 2):
            a0 = self.coeffs[i] % KYBER_Q
            a1 = self.coeffs[i + 1] % KYBER_Q
            result.append(a0 & 0xFF)
            result.append(((a0 >> 8) | (a1 << 4)) & 0xFF)
            result.append((a1 >> 4) & 0xFF)
        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "KyberPoly":
        """Deserialize polynomial from bytes."""
        coeffs = []
        for i in range(0, 3 * KYBER_N // 2, 3):
            b0, b1, b2 = data[i], data[i + 1], data[i + 2]
            coeffs.append(b0 | ((b1 & 0x0F) << 8))
            coeffs.append((b1 >> 4) | (b2 << 4))
        return cls([c % KYBER_Q for c in coeffs])

    @classmethod
    def cbd(cls, eta: int, seed: bytes) -> "KyberPoly":
        """Sample from centered binomial distribution CBD_eta.

        Each coefficient is sampled as (sum of eta bits) - (sum of eta bits),
        giving values in [-eta, eta]. Used for secret and error polynomials.

        Args:
            eta: Noise parameter (2 or 3 for ML-KEM).
            seed: 32-byte PRF seed used to expand pseudorandom bits.
        """
        # Use SHAKE-256 to expand seed
        shake = hashlib.shake_256()
        shake.update(seed)
        buf = shake.digest(64 * eta)

        coeffs = []
        bit_offset = 0
        for _ in range(KYBER_N):
            a = 0
            b = 0
            for j in range(eta):
                byte_idx = (bit_offset + j) // 8
                bit_in_byte = (bit_offset + j) % 8
                a += (buf[byte_idx] >> bit_in_byte) & 1
            for j in range(eta):
                byte_idx = (bit_offset + eta + j) // 8
                bit_in_byte = (bit_offset + eta + j) % 8
                b += (buf[byte_idx] >> bit_in_byte) & 1
            coeffs.append((a - b) % KYBER_Q)
            bit_offset += 2 * eta
        return cls(coeffs)

    @classmethod
    def sample_uniform(cls, seed: bytes, i: int, j: int) -> "KyberPoly":
        """Sample uniform polynomial from XOF (SHAKE-128).

        Used to generate the public matrix A. The indices i, j are the row
        and column position in the module matrix and are appended to the seed
        so that each entry is independently and uniformly distributed.

        Args:
            seed: 32-byte public seed rho.
            i: Row index of the matrix entry.
            j: Column index of the matrix entry.
        """
        xof_input = seed + bytes([i, j])
        shake = hashlib.shake_128()
        shake.update(xof_input)
        stream = shake.digest(840)  # Enough for rejection sampling

        coeffs = []
        pos = 0
        while len(coeffs) < KYBER_N and pos + 2 < len(stream):
            b0, b1, b2 = stream[pos], stream[pos + 1], stream[pos + 2]
            d1 = b0 | ((b1 & 0x0F) << 8)
            d2 = (b1 >> 4) | (b2 << 4)
            pos += 3
            if d1 < KYBER_Q:
                coeffs.append(d1)
            if d2 < KYBER_Q and len(coeffs) < KYBER_N:
                coeffs.append(d2)

        # Pad if needed
        while len(coeffs) < KYBER_N:
            coeffs.append(0)

        return cls(coeffs[:KYBER_N])


class KyberPolyVec:
    """Vector of Kyber polynomials."""

    def __init__(self, k: int):
        self.k = k
        self.polys: list[KyberPoly] = [KyberPoly() for _ in range(k)]

    def add(self, other: "KyberPolyVec") -> "KyberPolyVec":
        result = KyberPolyVec(self.k)
        result.polys = [a.add(b) for a, b in zip(self.polys, other.polys)]
        return result

    def ntt(self) -> "KyberPolyVec":
        result = KyberPolyVec(self.k)
        result.polys = [p.ntt() for p in self.polys]
        return result

    def ntt_inv(self) -> "KyberPolyVec":
        result = KyberPolyVec(self.k)
        result.polys = [p.ntt_inv() for p in self.polys]
        return result

    def dot(self, other: "KyberPolyVec") -> KyberPoly:
        """Compute inner product in NTT domain."""
        result = KyberPoly()
        for a, b in zip(self.polys, other.polys):
            result = result.add(a.pointwise_mul(b))
        return result

    def to_bytes(self) -> bytes:
        return b"".join(p.to_bytes() for p in self.polys)

    @classmethod
    def from_bytes(cls, data: bytes, k: int) -> "KyberPolyVec":
        poly_size = 384  # 256 * 12 / 8
        vec = cls(k)
        for i in range(k):
            vec.polys[i] = KyberPoly.from_bytes(data[i * poly_size: (i + 1) * poly_size])
        return vec
