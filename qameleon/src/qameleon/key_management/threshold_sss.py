"""Shamir's Secret Sharing over GF(2^8)."""

import os
from dataclasses import dataclass


# GF(2^8) with primitive polynomial x^8 + x^4 + x^3 + x + 1 (AES polynomial)
_GF_EXP = [0] * 512
_GF_LOG = [0] * 256


def _init_gf() -> None:
    x = 1
    for i in range(255):
        _GF_EXP[i] = x
        _GF_LOG[x] = i
        # Use generator 3 (0x03) with AES polynomial x^8+x^4+x^3+x+1
        x ^= (x << 1) ^ (0x1B if x & 0x80 else 0)
        x &= 0xFF
    for i in range(255, 512):
        _GF_EXP[i] = _GF_EXP[i - 255]


_init_gf()


def _gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _GF_EXP[_GF_LOG[a] + _GF_LOG[b]]


def _gf_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(2^8)")
    if a == 0:
        return 0
    return _GF_EXP[(_GF_LOG[a] - _GF_LOG[b]) % 255]


def _gf_pow(x: int, power: int) -> int:
    if x == 0:
        return 0
    return _GF_EXP[(_GF_LOG[x] * power) % 255]


def _gf_inv(x: int) -> int:
    return _GF_EXP[255 - _GF_LOG[x]]


@dataclass
class Share:
    """A single Shamir secret share."""
    x: int      # Share index (1..n)
    y: bytes    # Share value (one byte per secret byte)


class ThresholdSecretSharing:
    """Shamir's Secret Sharing over GF(2^8)."""

    @staticmethod
    def split(secret: bytes, k: int, n: int) -> list[Share]:
        """Split secret into n shares, requiring k to reconstruct."""
        if k > n:
            raise ValueError("k must be <= n")
        if k < 2:
            raise ValueError("k must be >= 2")

        shares = [bytearray(len(secret)) for _ in range(n)]

        for i, byte in enumerate(secret):
            # Random polynomial coefficients a_1..a_{k-1}
            coeffs = [byte] + list(os.urandom(k - 1))

            for x in range(1, n + 1):
                y = 0
                for j in range(k - 1, -1, -1):
                    y = _gf_mul(y, x) ^ coeffs[j]
                shares[x - 1][i] = y

        return [Share(x=i + 1, y=bytes(shares[i])) for i in range(n)]

    @staticmethod
    def reconstruct(shares: list[Share]) -> bytes:
        """Reconstruct secret from shares using Lagrange interpolation."""
        if not shares:
            raise ValueError("No shares provided")

        secret_len = len(shares[0].y)
        secret = bytearray(secret_len)

        for i in range(secret_len):
            ys = [(s.x, s.y[i]) for s in shares]
            # Lagrange interpolation at x=0
            result = 0
            for j, (xj, yj) in enumerate(ys):
                num = yj
                den = 1
                for k, (xk, _) in enumerate(ys):
                    if k != j:
                        num = _gf_mul(num, xk)
                        den = _gf_mul(den, xj ^ xk)
                result ^= _gf_mul(num, _gf_inv(den))
            secret[i] = result

        return bytes(secret)
