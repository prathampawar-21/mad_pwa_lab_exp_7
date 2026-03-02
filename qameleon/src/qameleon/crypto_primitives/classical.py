"""Classical cryptographic primitives: X25519 ECDH and Ed25519."""

import hashlib
import hmac
import os
import struct
from dataclasses import dataclass


# Curve25519 base point
_P = 2**255 - 19
_A24 = 121665


def _clamp(k: bytes) -> int:
    """Clamp scalar for X25519."""
    k_list = list(k)
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return int.from_bytes(bytes(k_list), 'little')


def _x25519_ladder(k: int, u: int) -> int:
    """Montgomery ladder for X25519."""
    x_1 = u
    x_2 = 1
    z_2 = 0
    x_3 = u
    z_3 = 1
    swap = 0

    for t in range(254, -1, -1):
        k_t = (k >> t) & 1
        swap ^= k_t
        # Conditional swap
        if swap:
            x_2, x_3 = x_3, x_2
            z_2, z_3 = z_3, z_2
        swap = k_t

        A = (x_2 + z_2) % _P
        AA = (A * A) % _P
        B = (x_2 - z_2) % _P
        BB = (B * B) % _P
        E = (AA - BB) % _P
        C = (x_3 + z_3) % _P
        D = (x_3 - z_3) % _P
        DA = (D * A) % _P
        CB = (C * B) % _P
        x_3 = pow(DA + CB, 2, _P)
        z_3 = (x_1 * pow(DA - CB, 2, _P)) % _P
        x_2 = (AA * BB) % _P
        z_2 = (E * (AA + _A24 * E)) % _P

    if swap:
        x_2, x_3 = x_3, x_2
        z_2, z_3 = z_3, z_2

    return (x_2 * pow(z_2, _P - 2, _P)) % _P


_BASE_U = 9


def x25519_generate() -> tuple[bytes, bytes]:
    """Generate X25519 key pair: (private_key, public_key)."""
    private = os.urandom(32)
    k = _clamp(private)
    public = _x25519_ladder(k, _BASE_U).to_bytes(32, 'little')
    return private, public


def x25519_shared_secret(private_key: bytes, peer_public_key: bytes) -> bytes:
    """Compute X25519 shared secret."""
    k = _clamp(private_key)
    u = int.from_bytes(peer_public_key, 'little')
    shared = _x25519_ladder(k, u).to_bytes(32, 'little')
    return shared


# Ed25519 constants
_L = 2**252 + 27742317777372353535851937790883648493
_q = 2**255 - 19
_d = -121665 * pow(121666, _q - 2, _q) % _q
_B_y = 4 * pow(5, _q - 2, _q) % _q
_B_x_sq = ((_B_y * _B_y - 1) * pow(_d * _B_y * _B_y + 1, _q - 2, _q)) % _q
_B_x = pow(_B_x_sq, (_q + 3) // 8, _q)
if (_B_x * _B_x - _B_x_sq) % _q != 0:
    _SQRT_M1 = pow(2, (_q - 1) // 4, _q)
    _B_x = (_B_x * _SQRT_M1) % _q
_B = (_B_x, _B_y, 1, (_B_x * _B_y) % _q)


def _ed25519_point_add(P: tuple, Q: tuple) -> tuple:
    """Add two Ed25519 points in extended coordinates."""
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _q
    b = (y1 + x1) * (y2 + x2) % _q
    c = t1 * 2 * _d * t2 % _q
    dd = z1 * 2 * z2 % _q
    e = (b - a) % _q
    f = (dd - c) % _q
    g = (dd + c) % _q
    h = (b + a) % _q
    return (e * f % _q, g * h % _q, f * g % _q, e * h % _q)


def _ed25519_scalar_mul(k: int, P: tuple) -> tuple:
    """Scalar multiplication for Ed25519."""
    Q = (0, 1, 1, 0)  # Identity
    while k:
        if k & 1:
            Q = _ed25519_point_add(Q, P)
        P = _ed25519_point_add(P, P)
        k >>= 1
    return Q


def _ed25519_encode_point(P: tuple) -> bytes:
    """Encode Ed25519 point."""
    x, y, z, _ = P
    zi = pow(z, _q - 2, _q)
    x = x * zi % _q
    y = y * zi % _q
    result = y.to_bytes(32, 'little')
    result = bytearray(result)
    result[-1] ^= (x & 1) << 7
    return bytes(result)


def ed25519_generate() -> tuple[bytes, bytes]:
    """Generate Ed25519 key pair: (private_key, public_key)."""
    seed = os.urandom(32)
    h = hashlib.sha512(seed).digest()
    a = list(h[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    scalar = int.from_bytes(bytes(a), 'little')
    public_point = _ed25519_scalar_mul(scalar, _B)
    public_key = _ed25519_encode_point(public_point)
    return seed, public_key


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message with Ed25519."""
    h = hashlib.sha512(seed).digest()
    a_bytes = bytearray(h[:32])
    a_bytes[0] &= 248
    a_bytes[31] &= 127
    a_bytes[31] |= 64
    a = int.from_bytes(bytes(a_bytes), 'little')

    public_point = _ed25519_scalar_mul(a, _B)
    public_key = _ed25519_encode_point(public_point)

    prefix = h[32:]
    r_hash = hashlib.sha512(prefix + message).digest()
    r = int.from_bytes(r_hash, 'little') % _L

    R_point = _ed25519_scalar_mul(r, _B)
    R = _ed25519_encode_point(R_point)

    k_hash = hashlib.sha512(R + public_key + message).digest()
    k = int.from_bytes(k_hash, 'little') % _L

    S = (r + k * a) % _L
    return R + S.to_bytes(32, 'little')


def _ed25519_decode_point(data: bytes) -> tuple:
    """Decode a compressed Ed25519 point."""
    if len(data) != 32:
        raise ValueError("Invalid point encoding")
    y_bytes = bytearray(data)
    sign_x = (y_bytes[-1] & 0x80) >> 7
    y_bytes[-1] &= 0x7F
    y = int.from_bytes(bytes(y_bytes), 'little')
    # Recover x: x^2 = (y^2 - 1) * modular_inverse(d*y^2 + 1)
    y2 = y * y % _q
    x2 = (y2 - 1) * pow(_d * y2 + 1, _q - 2, _q) % _q
    if x2 == 0:
        if sign_x:
            raise ValueError("Invalid point")
        return (0, y, 1, 0)
    x = pow(x2, (_q + 3) // 8, _q)
    if (x * x - x2) % _q != 0:
        _SQRT_M1 = pow(2, (_q - 1) // 4, _q)
        x = x * _SQRT_M1 % _q
    if (x * x - x2) % _q != 0:
        raise ValueError("Invalid point: x^2 mismatch")
    if x % 2 != sign_x:
        x = _q - x
    return (x, y, 1, x * y % _q)


def _ed25519_point_neg(P: tuple) -> tuple:
    """Negate an Ed25519 point."""
    x, y, z, t = P
    return ((-x) % _q, y, z, (-t) % _q)


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""
    if len(signature) != 64:
        return False
    try:
        S_int = int.from_bytes(signature[32:], 'little')
        if S_int >= _L:
            return False
        R_enc = signature[:32]
        R = _ed25519_decode_point(R_enc)
        A = _ed25519_decode_point(public_key)
        k_hash = hashlib.sha512(R_enc + public_key + message).digest()
        k = int.from_bytes(k_hash, 'little') % _L
        # Verify: S*B == R + k*A
        sB = _ed25519_scalar_mul(S_int, _B)
        kA = _ed25519_scalar_mul(k, A)
        RkA = _ed25519_point_add(R, kA)
        return _ed25519_encode_point(sB) == _ed25519_encode_point(RkA)
    except Exception:
        return False


@dataclass
class ClassicalKeyExchange:
    """X25519 ECDH key exchange."""
    private_key: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "ClassicalKeyExchange":
        priv, pub = x25519_generate()
        return cls(private_key=priv, public_key=pub)

    def shared_secret(self, peer_public_key: bytes) -> bytes:
        return x25519_shared_secret(self.private_key, peer_public_key)


@dataclass
class ClassicalSignature:
    """Ed25519 digital signature."""
    seed: bytes
    public_key: bytes

    @classmethod
    def generate(cls) -> "ClassicalSignature":
        seed, pub = ed25519_generate()
        return cls(seed=seed, public_key=pub)

    def sign(self, message: bytes) -> bytes:
        return ed25519_sign(self.seed, message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        return ed25519_verify(self.public_key, message, signature)
