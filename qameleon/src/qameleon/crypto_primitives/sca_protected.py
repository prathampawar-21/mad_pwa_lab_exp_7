"""Side-channel attack protection: constant-time comparison, random delays, masking."""

import hashlib
import hmac
import os
import time
from typing import Callable, TypeVar

T = TypeVar("T")


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time byte string comparison to prevent timing attacks."""
    return hmac.compare_digest(a, b)


def random_delay(min_us: int = 10, max_us: int = 100) -> None:
    """Introduce a random delay to prevent timing side-channel attacks."""
    delay_bytes = os.urandom(1)
    delay_range = max_us - min_us
    delay_us = min_us + (delay_bytes[0] * delay_range) // 256
    time.sleep(delay_us / 1_000_000)


def mask_value(value: bytes) -> tuple[bytes, bytes]:
    """Apply random masking to protect against power analysis.
    
    Returns:
        (masked_value, mask) where masked_value ^ mask = value
    """
    mask = os.urandom(len(value))
    masked = bytes(a ^ b for a, b in zip(value, mask))
    return masked, mask


def unmask_value(masked: bytes, mask: bytes) -> bytes:
    """Remove mask from a masked value."""
    return bytes(a ^ b for a, b in zip(masked, mask))


class SCAProtectedOperation:
    """Wrapper for side-channel protected cryptographic operations."""

    def __init__(self, enable_random_delay: bool = True, enable_masking: bool = True) -> None:
        self.enable_random_delay = enable_random_delay
        self.enable_masking = enable_masking

    def run(self, operation: Callable[[], T]) -> T:
        """Run a cryptographic operation with SCA protections."""
        if self.enable_random_delay:
            random_delay()
        result = operation()
        if self.enable_random_delay:
            random_delay()
        return result

    def protected_compare(self, a: bytes, b: bytes) -> bool:
        """Constant-time comparison with random delay."""
        if self.enable_random_delay:
            random_delay()
        return constant_time_compare(a, b)
