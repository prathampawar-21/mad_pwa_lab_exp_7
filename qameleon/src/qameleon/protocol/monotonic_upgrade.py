"""Monotonic upgrade enforcer - prevents cryptographic downgrade attacks."""

from dataclasses import dataclass
from typing import Optional

from qameleon.exceptions import DowngradeAttemptError


@dataclass
class CryptoParameters:
    """Current cryptographic parameter baseline."""
    kem_level: int = 0          # ML-KEM security level (512/768/1024)
    sig_level: int = 0          # ML-DSA security level (44/65/87)
    symmetric_bits: int = 0     # Symmetric key bits (128/256)
    sca_level: int = 0          # SCA protection level (0-3)


class MonotonicUpgradeEnforcer:
    """Ensures cryptographic parameters only increase over time."""

    def __init__(self) -> None:
        self._baseline: Optional[CryptoParameters] = None

    def set_baseline(self, params: CryptoParameters) -> None:
        """Set the initial parameter baseline."""
        self._baseline = params

    def validate_upgrade(self, new_params: CryptoParameters) -> None:
        """Validate that new parameters represent an upgrade or equal, never downgrade."""
        if self._baseline is None:
            self._baseline = new_params
            return

        checks = [
            ("KEM level", self._baseline.kem_level, new_params.kem_level),
            ("signature level", self._baseline.sig_level, new_params.sig_level),
            ("symmetric bits", self._baseline.symmetric_bits, new_params.symmetric_bits),
            ("SCA level", self._baseline.sca_level, new_params.sca_level),
        ]

        for name, old_val, new_val in checks:
            if new_val < old_val:
                raise DowngradeAttemptError(
                    f"Downgrade attempt detected: {name} would decrease "
                    f"from {old_val} to {new_val}"
                )

        # Update baseline to new values (ratchet forward)
        self._baseline = CryptoParameters(
            kem_level=max(self._baseline.kem_level, new_params.kem_level),
            sig_level=max(self._baseline.sig_level, new_params.sig_level),
            symmetric_bits=max(self._baseline.symmetric_bits, new_params.symmetric_bits),
            sca_level=max(self._baseline.sca_level, new_params.sca_level),
        )

    def get_baseline(self) -> Optional[CryptoParameters]:
        return self._baseline
