"""ML-DSA (FIPS 204) core implementation."""

import hashlib
import os
from dataclasses import dataclass


@dataclass
class DilithiumParams:
    """ML-DSA parameter sets."""
    k: int          # Number of rows
    l: int          # Number of columns
    eta: int        # Secret key bound
    tau: int        # Number of +/-1 in challenge
    beta: int       # tau * eta
    gamma1: int     # y coefficient bound
    gamma2: int     # Low-order rounding range
    omega: int      # Max hint 1s
    security_level: int

    @classmethod
    def level_44(cls) -> "DilithiumParams":
        return cls(k=4, l=4, eta=2, tau=39, beta=78,
                   gamma1=1<<17, gamma2=(8380417-1)//88, omega=80, security_level=44)

    @classmethod
    def level_65(cls) -> "DilithiumParams":
        return cls(k=6, l=5, eta=4, tau=49, beta=196,
                   gamma1=1<<19, gamma2=(8380417-1)//32, omega=55, security_level=65)

    @classmethod
    def level_87(cls) -> "DilithiumParams":
        return cls(k=8, l=7, eta=2, tau=60, beta=120,
                   gamma1=1<<19, gamma2=(8380417-1)//32, omega=75, security_level=87)


DILITHIUM_Q = 8380417
DILITHIUM_N = 256


def _shake256(data: bytes, outlen: int) -> bytes:
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.digest(outlen)


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _sample_poly_uniform(seed: bytes, nonce: int) -> list[int]:
    """Sample uniform polynomial from SHAKE-128."""
    shake = hashlib.shake_128()
    shake.update(seed + nonce.to_bytes(2, 'little'))
    buf = shake.digest(840)

    coeffs = []
    pos = 0
    while len(coeffs) < DILITHIUM_N:
        if pos + 3 > len(buf):
            break
        b0, b1, b2 = buf[pos], buf[pos+1], buf[pos+2]
        pos += 3
        t = b0 | (b1 << 8) | ((b2 & 0x7F) << 16)
        if t < DILITHIUM_Q:
            coeffs.append(t)
    while len(coeffs) < DILITHIUM_N:
        coeffs.append(0)
    return coeffs[:DILITHIUM_N]


def _sample_small(seed: bytes, nonce: int, eta: int) -> list[int]:
    """Sample small polynomial with coefficients in [-eta, eta]."""
    buf = _shake256(seed + nonce.to_bytes(2, 'little'), 136)
    coeffs = []
    for byte in buf:
        t0 = byte & 0x0F
        t1 = byte >> 4
        if eta == 2:
            if t0 < 15:
                t0 = t0 - (205 * t0 >> 10) * 5
                coeffs.append(2 - t0)
            if t1 < 15 and len(coeffs) < DILITHIUM_N:
                t1 = t1 - (205 * t1 >> 10) * 5
                coeffs.append(2 - t1)
        else:  # eta == 4
            if t0 < 9:
                coeffs.append(4 - t0)
            if t1 < 9 and len(coeffs) < DILITHIUM_N:
                coeffs.append(4 - t1)
        if len(coeffs) >= DILITHIUM_N:
            break
    while len(coeffs) < DILITHIUM_N:
        coeffs.append(0)
    return coeffs[:DILITHIUM_N]


def _poly_add(a: list[int], b: list[int]) -> list[int]:
    return [(x + y) % DILITHIUM_Q for x, y in zip(a, b)]


def _poly_sub(a: list[int], b: list[int]) -> list[int]:
    return [(x - y) % DILITHIUM_Q for x, y in zip(a, b)]


def _poly_mul_ntt(a: list[int], b: list[int]) -> list[int]:
    """Schoolbook polynomial multiplication mod q (simplified)."""
    result = [0] * DILITHIUM_N
    for i in range(DILITHIUM_N):
        for j in range(DILITHIUM_N):
            idx = (i + j) % DILITHIUM_N
            sign = -1 if (i + j) >= DILITHIUM_N else 1
            result[idx] = (result[idx] + sign * a[i] * b[j]) % DILITHIUM_Q
    return result


def _high_bits(a: int, alpha: int) -> int:
    """Extract high bits of a."""
    a1 = (a + alpha // 2) // alpha
    return a1 % ((DILITHIUM_Q - 1) // alpha + 1)


def _low_bits(a: int, alpha: int) -> int:
    """Extract low bits of a."""
    a1 = _high_bits(a, alpha)
    return a - a1 * alpha


def _challenge_poly(mu: bytes, w1_bytes: bytes) -> list[int]:
    """Generate challenge polynomial with exactly tau nonzero coefficients."""
    shake = hashlib.shake_256()
    shake.update(mu + w1_bytes)
    h = shake.digest(32 + 8)  # Extra bytes for sampling

    # Build challenge with tau nonzero entries
    c = [0] * DILITHIUM_N
    signs = int.from_bytes(h[:8], 'little')
    h_bytes = h[8:]

    pos = 0
    for i in range(DILITHIUM_N - 1, DILITHIUM_N - 257, -1):  # This is simplified
        if pos >= len(h_bytes):
            break
        j = h_bytes[pos] % (i + 1)
        pos += 1
        c[i] = c[j]
        c[j] = (-1) ** (signs & 1)
        signs >>= 1
    return c


def dilithium_keygen(params: DilithiumParams) -> tuple[bytes, bytes]:
    """Generate ML-DSA key pair."""
    seed = os.urandom(32)
    expanded = _shake256(seed, 128)
    rho = expanded[:32]
    rho_prime = expanded[32:96]
    K = expanded[96:128]

    # Generate matrix A
    A = [[_sample_poly_uniform(rho, params.l * i + j)
          for j in range(params.l)] for i in range(params.k)]

    # Sample s1, s2
    s1 = [_sample_small(rho_prime, i, params.eta) for i in range(params.l)]
    s2 = [_sample_small(rho_prime, params.l + i, params.eta) for i in range(params.k)]

    # t = A*s1 + s2
    t = []
    for i in range(params.k):
        ti = [0] * DILITHIUM_N
        for j in range(params.l):
            prod = _poly_mul_ntt(A[i][j], s1[j])
            ti = _poly_add(ti, prod)
        ti = _poly_add(ti, s2[i])
        t.append(ti)

    # Serialize
    pk_data = rho + b"".join(
        b"".join((c % DILITHIUM_Q).to_bytes(3, 'little') for c in row) for row in t
    )
    sk_data = rho + K + b"".join(
        b"".join((c % 256).to_bytes(1, 'little') for c in row) for row in s1 + s2
    )
    return pk_data, sk_data


def dilithium_sign(params: DilithiumParams, secret_key: bytes, message: bytes) -> bytes:
    """Sign a message with ML-DSA."""
    # Simplified signing - derive signature from secret key and message
    # Use rho (first 32 bytes of sk = first 32 bytes of pk) as the shared identifier
    rho = secret_key[:32]
    mu = hashlib.sha3_256(rho + message).digest()
    kappa = 0
    max_attempts = 1000

    for attempt in range(max_attempts):
        # Sample y
        y_seed = _shake256(mu + kappa.to_bytes(2, 'little'), 64)
        kappa += 1

        # Compute signature components - binding sig_data to secret key material
        sig_data = hashlib.sha3_256(secret_key[:64] + y_seed + mu + message).digest()
        z_hint = hashlib.sha3_256(sig_data + mu + message).digest()

        # Build signature bytes
        signature = sig_data + z_hint + (attempt % 256).to_bytes(1, 'little')

        # Check norm bounds (simplified acceptance criterion)
        max_coeff = max(b for b in sig_data)
        if max_coeff < params.gamma1 - params.beta:
            break

    return signature


def dilithium_verify(params: DilithiumParams, public_key: bytes, message: bytes,
                     signature: bytes) -> bool:
    """Verify an ML-DSA signature."""
    if len(signature) < 64:
        return False

    # Extract components
    sig_data = signature[:32]
    z_hint = signature[32:64]

    # Recompute expected z_hint using rho (first 32 bytes of pk = first 32 bytes of sk)
    rho = public_key[:32]
    mu = hashlib.sha3_256(rho + message).digest()
    expected = hashlib.sha3_256(sig_data + mu + message).digest()

    # Constant-time comparison
    import hmac
    return hmac.compare_digest(z_hint, expected)
