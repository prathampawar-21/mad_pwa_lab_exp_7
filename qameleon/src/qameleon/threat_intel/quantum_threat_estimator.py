"""Quantum threat level estimation."""

from dataclasses import dataclass
from enum import IntEnum


class QuantumThreatLevel(IntEnum):
    """Estimated quantum threat levels."""
    NONE = 0            # No credible quantum threat
    HARVEST_NOW = 1     # Harvest now, decrypt later attacks possible
    EARLY_FAULT_TOLERANT = 2  # Early fault-tolerant quantum computers exist
    CRYPTOGRAPHICALLY_RELEVANT = 3  # RSA/ECC breakable
    CRYPTOGRAPHIC = 4   # Full quantum cryptanalysis capability


@dataclass
class QuantumThreatAssessment:
    """Detailed quantum threat assessment."""
    level: QuantumThreatLevel
    score: float            # 0.0 - 1.0
    years_to_relevance: float
    details: str


class QuantumThreatEstimator:
    """Estimates quantum threat level based on adversary capability."""

    def __init__(self, adversary_capability: float = 0.1) -> None:
        """Initialize with adversary quantum capability (0.0 - 1.0)."""
        self._capability = max(0.0, min(1.0, adversary_capability))

    def estimate(self) -> QuantumThreatAssessment:
        """Estimate current quantum threat level."""
        cap = self._capability

        if cap < 0.1:
            level = QuantumThreatLevel.NONE
            years = 15.0
            details = "No credible near-term quantum threat"
        elif cap < 0.3:
            level = QuantumThreatLevel.HARVEST_NOW
            years = 10.0
            details = "Harvest-now-decrypt-later attacks possible"
        elif cap < 0.6:
            level = QuantumThreatLevel.EARLY_FAULT_TOLERANT
            years = 5.0
            details = "Early fault-tolerant quantum computers observed"
        elif cap < 0.85:
            level = QuantumThreatLevel.CRYPTOGRAPHICALLY_RELEVANT
            years = 2.0
            details = "Classical cryptography under threat"
        else:
            level = QuantumThreatLevel.CRYPTOGRAPHIC
            years = 0.0
            details = "Full quantum cryptanalytic capability"

        return QuantumThreatAssessment(
            level=level,
            score=cap,
            years_to_relevance=years,
            details=details,
        )

    def get_score(self) -> float:
        """Get normalized threat score (0.0 - 1.0)."""
        return self._capability

    def update_capability(self, new_capability: float) -> None:
        """Update adversary capability estimate."""
        self._capability = max(0.0, min(1.0, new_capability))
