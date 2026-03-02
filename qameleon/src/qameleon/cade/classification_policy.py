"""Classification levels and policy requirements."""

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional

from qameleon.exceptions import PolicyViolationError


class ClassificationLevel(IntEnum):
    """Security classification levels."""
    UNCLASSIFIED = 0
    CONFIDENTIAL = 1
    SECRET = 2
    TOP_SECRET = 3
    TOP_SECRET_SCI = 4


@dataclass
class PolicyRequirements:
    """Cryptographic requirements for a classification level."""
    min_kem_nist_level: int
    min_sig_nist_level: int
    allowed_kem_algorithms: list[str]
    allowed_sig_algorithms: list[str]
    require_hybrid: bool
    require_forward_secrecy: bool
    max_key_lifetime_seconds: float


class ClassificationPolicy:
    """Defines and enforces cryptographic policy per classification level."""

    _REQUIREMENTS: dict[ClassificationLevel, PolicyRequirements] = {
        ClassificationLevel.UNCLASSIFIED: PolicyRequirements(
            min_kem_nist_level=1,
            min_sig_nist_level=1,
            allowed_kem_algorithms=["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"],
            allowed_sig_algorithms=["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"],
            require_hybrid=False,
            require_forward_secrecy=False,
            max_key_lifetime_seconds=86400.0,
        ),
        ClassificationLevel.CONFIDENTIAL: PolicyRequirements(
            min_kem_nist_level=1,
            min_sig_nist_level=1,
            allowed_kem_algorithms=["ML-KEM-768", "ML-KEM-1024"],
            allowed_sig_algorithms=["ML-DSA-65", "ML-DSA-87"],
            require_hybrid=True,
            require_forward_secrecy=True,
            max_key_lifetime_seconds=28800.0,
        ),
        ClassificationLevel.SECRET: PolicyRequirements(
            min_kem_nist_level=3,
            min_sig_nist_level=3,
            allowed_kem_algorithms=["ML-KEM-768", "ML-KEM-1024"],
            allowed_sig_algorithms=["ML-DSA-65", "ML-DSA-87"],
            require_hybrid=True,
            require_forward_secrecy=True,
            max_key_lifetime_seconds=3600.0,
        ),
        ClassificationLevel.TOP_SECRET: PolicyRequirements(
            min_kem_nist_level=5,
            min_sig_nist_level=5,
            allowed_kem_algorithms=["ML-KEM-1024"],
            allowed_sig_algorithms=["ML-DSA-87"],
            require_hybrid=True,
            require_forward_secrecy=True,
            max_key_lifetime_seconds=1800.0,
        ),
        ClassificationLevel.TOP_SECRET_SCI: PolicyRequirements(
            min_kem_nist_level=5,
            min_sig_nist_level=5,
            allowed_kem_algorithms=["ML-KEM-1024"],
            allowed_sig_algorithms=["ML-DSA-87"],
            require_hybrid=True,
            require_forward_secrecy=True,
            max_key_lifetime_seconds=900.0,
        ),
    }

    @classmethod
    def get_requirements(cls, level: ClassificationLevel) -> PolicyRequirements:
        """Get policy requirements for a classification level."""
        return cls._REQUIREMENTS[level]

    @classmethod
    def validate_kem(cls, level: ClassificationLevel, kem_algorithm: str) -> bool:
        """Check if a KEM algorithm is allowed for a classification level."""
        req = cls._REQUIREMENTS[level]
        if kem_algorithm not in req.allowed_kem_algorithms:
            raise PolicyViolationError(
                f"KEM algorithm {kem_algorithm} not allowed for {level.name}"
            )
        return True

    @classmethod
    def validate_sig(cls, level: ClassificationLevel, sig_algorithm: str) -> bool:
        """Check if a signature algorithm is allowed."""
        req = cls._REQUIREMENTS[level]
        if sig_algorithm not in req.allowed_sig_algorithms:
            raise PolicyViolationError(
                f"Signature algorithm {sig_algorithm} not allowed for {level.name}"
            )
        return True

    @classmethod
    def validate_cross_domain(
        cls, source: ClassificationLevel, target: ClassificationLevel
    ) -> bool:
        """Validate that cross-domain data flow is permitted."""
        if target < source:
            raise PolicyViolationError(
                f"Write-down denied: {source.name} -> {target.name}"
            )
        return True

    @classmethod
    def negotiate_session_level(
        cls, level_a: ClassificationLevel, level_b: ClassificationLevel
    ) -> ClassificationLevel:
        """Negotiate session classification level (take the higher)."""
        return max(level_a, level_b)
