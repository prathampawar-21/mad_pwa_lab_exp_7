"""CADE decision engine for algorithm selection."""

from dataclasses import dataclass
from typing import Optional

from qameleon.cade.algorithm_registry import AlgorithmRegistry
from qameleon.cade.classification_policy import ClassificationLevel, ClassificationPolicy
from qameleon.cade.cost_model import CostModel, DeviceCapability


@dataclass
class CADEDecision:
    """Decision made by the CADE engine."""
    selected_kem: str
    selected_sig: str
    security_score: float
    latency_ms: float
    energy_mj: float
    rationale: str


class CADEEngine:
    """Classification-Aware Decision Engine for algorithm selection."""

    # Weights for multi-objective scoring
    W_SECURITY = 0.5
    W_LATENCY = 0.25
    W_ENERGY = 0.15
    W_BANDWIDTH = 0.10

    def decide(
        self,
        classification: ClassificationLevel,
        device: DeviceCapability,
        threat_score: float = 0.0,
        mission_priority: str = "balanced",
    ) -> CADEDecision:
        """Select optimal algorithms given constraints.
        
        Args:
            classification: Required security classification
            device: Device hardware capabilities
            threat_score: Current threat level (0-1)
            mission_priority: "balanced", "latency", "security", or "energy"
        """
        requirements = ClassificationPolicy.get_requirements(classification)
        allowed_kem = requirements.allowed_kem_algorithms
        allowed_sig = requirements.allowed_sig_algorithms

        # Filter to algorithms that fit on device
        viable_kem = [k for k in allowed_kem if CostModel.fits_device(k, device)]
        viable_sig = [s for s in allowed_sig if CostModel.fits_device(s, device)]

        if not viable_kem:
            viable_kem = [allowed_kem[-1]]  # Fallback to highest
        if not viable_sig:
            viable_sig = [allowed_sig[-1]]

        # Adjust weights based on priority and threat
        w_sec = self.W_SECURITY + 0.2 * threat_score
        w_lat = self.W_LATENCY if mission_priority != "security" else 0.1
        w_energy = self.W_ENERGY

        best_kem = self._select_best(viable_kem, device, w_sec, w_lat, w_energy, "KEM")
        best_sig = self._select_best(viable_sig, device, w_sec, w_lat, w_energy, "SIG")

        kem_cost = CostModel.estimate(best_kem, device)
        sig_cost = CostModel.estimate(best_sig, device)

        rationale = (
            f"Selected {best_kem} + {best_sig} for {classification.name} "
            f"classification with threat_score={threat_score:.2f}. "
            f"Estimated latency: {kem_cost.latency_ms + sig_cost.latency_ms:.2f}ms"
        )

        kem_profile = AlgorithmRegistry.get(best_kem)
        return CADEDecision(
            selected_kem=best_kem,
            selected_sig=best_sig,
            security_score=kem_profile.nist_level / 5.0,
            latency_ms=kem_cost.latency_ms + sig_cost.latency_ms,
            energy_mj=kem_cost.energy_mj + sig_cost.energy_mj,
            rationale=rationale,
        )

    @staticmethod
    def _select_best(
        algorithms: list[str],
        device: DeviceCapability,
        w_sec: float,
        w_lat: float,
        w_energy: float,
        category: str,
    ) -> str:
        """Select the best algorithm using multi-objective scoring."""
        if len(algorithms) == 1:
            return algorithms[0]

        # Get max values for normalization
        costs = [CostModel.estimate(a, device) for a in algorithms]
        profiles = [AlgorithmRegistry.get(a) for a in algorithms]

        max_lat = max(c.latency_ms for c in costs) or 1.0
        max_energy = max(c.energy_mj for c in costs) or 1.0
        max_level = max(p.nist_level for p in profiles) or 1

        best_score = -1.0
        best_algo = algorithms[0]

        for algo, cost, profile in zip(algorithms, costs, profiles):
            # Security: higher is better
            s_score = profile.nist_level / max_level
            # Latency: lower is better (inverted)
            l_score = 1.0 - (cost.latency_ms / max_lat)
            # Energy: lower is better (inverted)
            e_score = 1.0 - (cost.energy_mj / max_energy)

            total = w_sec * s_score + w_lat * l_score + w_energy * e_score
            if total > best_score:
                best_score = total
                best_algo = algo

        return best_algo
