"""C acceleration loader - loads compiled shared libraries via ctypes with Python fallback."""

import ctypes
import os
from pathlib import Path
from typing import Optional

_lib_dir = Path(__file__).parent / "lib"
_kyber_lib: Optional[ctypes.CDLL] = None
_keccak_lib: Optional[ctypes.CDLL] = None
_accelerated = False


def _try_load_libs() -> bool:
    global _kyber_lib, _keccak_lib, _accelerated
    try:
        import platform
        suffix = {"Windows": ".dll", "Darwin": ".dylib"}.get(platform.system(), ".so")
        ntt_path = _lib_dir / f"libntt{suffix}"
        keccak_path = _lib_dir / f"libkeccak{suffix}"
        if ntt_path.exists():
            _kyber_lib = ctypes.CDLL(str(ntt_path))
            _kyber_lib.kyber_ntt_c.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int]
            _kyber_lib.kyber_ntt_c.restype = None
            _kyber_lib.kyber_ntt_inv_c.argtypes = [ctypes.POINTER(ctypes.c_int32), ctypes.c_int]
            _kyber_lib.kyber_ntt_inv_c.restype = None
        if keccak_path.exists():
            _keccak_lib = ctypes.CDLL(str(keccak_path))
            _keccak_lib.sha3_256_c.argtypes = [
                ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_uint8)
            ]
            _keccak_lib.sha3_256_c.restype = None
        _accelerated = _kyber_lib is not None
        return _accelerated
    except Exception:
        return False


_try_load_libs()


def is_accelerated() -> bool:
    """Return True if C acceleration libraries are loaded."""
    return _accelerated


def c_kyber_ntt(coeffs: list[int]) -> list[int]:
    """NTT via C library if available, otherwise pure Python."""
    if _kyber_lib is not None:
        arr = (ctypes.c_int32 * 256)(*coeffs)
        _kyber_lib.kyber_ntt_c(arr, 256)
        return list(arr)
    from qameleon.crypto_primitives.ntt import kyber_ntt
    return kyber_ntt(coeffs)


def c_kyber_ntt_inv(coeffs: list[int]) -> list[int]:
    """Inverse NTT via C library if available."""
    if _kyber_lib is not None:
        arr = (ctypes.c_int32 * 256)(*coeffs)
        _kyber_lib.kyber_ntt_inv_c(arr, 256)
        return list(arr)
    from qameleon.crypto_primitives.ntt import kyber_ntt_inv
    return kyber_ntt_inv(coeffs)


def c_sha3_256(data: bytes) -> bytes:
    """SHA3-256 via C library if available."""
    if _keccak_lib is not None:
        out = (ctypes.c_uint8 * 32)()
        data_arr = (ctypes.c_uint8 * len(data))(*data)
        _keccak_lib.sha3_256_c(data_arr, len(data), out)
        return bytes(out)
    import hashlib
    return hashlib.sha3_256(data).digest()


def c_sha3_512(data: bytes) -> bytes:
    """SHA3-512 via C library if available."""
    if _keccak_lib is not None and hasattr(_keccak_lib, 'sha3_512_c'):
        out = (ctypes.c_uint8 * 64)()
        data_arr = (ctypes.c_uint8 * len(data))(*data)
        _keccak_lib.sha3_512_c(data_arr, len(data), out)
        return bytes(out)
    import hashlib
    return hashlib.sha3_512(data).digest()


def c_shake256(data: bytes, length: int) -> bytes:
    """SHAKE-256 via C library if available."""
    if _keccak_lib is not None and hasattr(_keccak_lib, 'shake256_c'):
        out = (ctypes.c_uint8 * length)()
        data_arr = (ctypes.c_uint8 * len(data))(*data)
        _keccak_lib.shake256_c(data_arr, len(data), out, length)
        return bytes(out)
    import hashlib
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.digest(length)
