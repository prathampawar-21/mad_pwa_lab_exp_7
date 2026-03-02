"""Unified threat score combining SCA, network, and quantum threats."""

import time
from dataclasses import dataclass
from typing import Optional

from qameleon.threat_intel.sca_detector import SCADetector
from qameleon.threat_intel.network_ids import NetworkIDS
from qameleon.threat_intel.quantum_threat_estimator import QuantumThreatEstimator


@dataclass
class ThreatSnapshot:
    """Combined threat assessment snapshot."""
    sca_score: float
    network_score: float
    quantum_score: float
    unified_score: float
    timestamp: float
    recommendation: str


class UnifiedThreatScorer:
    """Combines multiple threat signals into a unified threat score (UTS)."""

    # Weights for each component
    W_SCA = 0.30
    W_NETWORK = 0.35
    W_QUANTUM = 0.35

    def __init__(
        self,
        sca_detector: Optional[SCADetector] = None,
        network_ids: Optional[NetworkIDS] = None,
        quantum_estimator: Optional[QuantumThreatEstimator] = None,
    ) -> None:
        self._sca = sca_detector or SCADetector()
        self._network = network_ids or NetworkIDS()
        self._quantum = quantum_estimator or QuantumThreatEstimator()

    def compute(self) -> ThreatSnapshot:
        """Compute unified threat score."""
        # SCA score: based on detected alerts
        sca_alerts = self._sca.detect()
        sca_score = max((a.severity for a in sca_alerts), default=0.0) if sca_alerts else 0.0

        # Quantum score
        quantum_score = self._quantum.get_score()

        # Network score (estimated from last analysis - 0 if no recent alerts)
        network_score = 0.0

        # Unified score
        uts = (
            self.W_SCA * sca_score
            + self.W_NETWORK * network_score
            + self.W_QUANTUM * quantum_score
        )

        recommendation = self._get_recommendation(uts)

        return ThreatSnapshot(
            sca_score=sca_score,
            network_score=network_score,
            quantum_score=quantum_score,
            unified_score=uts,
            timestamp=time.time(),
            recommendation=recommendation,
        )

    @staticmethod
    def _get_recommendation(uts: float) -> str:
        if uts < 0.3:
            return "NORMAL - Continue with current security posture"
        elif uts < 0.5:
            return "ELEVATED - Consider increasing key rotation frequency"
        elif uts < 0.7:
            return "HIGH - Upgrade to ML-KEM-1024 + ML-DSA-87, increase rekeying"
        else:
            return "CRITICAL - Maximum security posture, immediate rekey required"
