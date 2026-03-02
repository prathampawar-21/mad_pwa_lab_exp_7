"""Side-channel attack detector."""

import statistics
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class SCAAlertType(Enum):
    TIMING_ANOMALY = "TIMING_ANOMALY"
    POWER_ANOMALY = "POWER_ANOMALY"


@dataclass
class SCAAlert:
    alert_type: SCAAlertType
    severity: float
    details: str


class SCADetector:
    """Detects side-channel attack patterns in timing/power measurements."""

    Z_SCORE_THRESHOLD = 3.0
    CV_THRESHOLD = 0.5
    MIN_SAMPLES = 10

    def __init__(self) -> None:
        self._timing_measurements: list[float] = []
        self._power_measurements: list[float] = []

    def add_measurement(
        self,
        timing_us: Optional[float] = None,
        power_mw: Optional[float] = None,
    ) -> None:
        """Add a timing or power measurement."""
        if timing_us is not None:
            self._timing_measurements.append(timing_us)
        if power_mw is not None:
            self._power_measurements.append(power_mw)

    def detect(self) -> list[SCAAlert]:
        """Analyze measurements for anomalies."""
        alerts = []

        if len(self._timing_measurements) >= self.MIN_SAMPLES:
            alert = self._analyze_measurements(
                self._timing_measurements, SCAAlertType.TIMING_ANOMALY
            )
            if alert:
                alerts.append(alert)

        if len(self._power_measurements) >= self.MIN_SAMPLES:
            alert = self._analyze_measurements(
                self._power_measurements, SCAAlertType.POWER_ANOMALY
            )
            if alert:
                alerts.append(alert)

        return alerts

    def _analyze_measurements(
        self, measurements: list[float], alert_type: SCAAlertType
    ) -> Optional[SCAAlert]:
        """Analyze a measurement series for anomalies."""
        mean = statistics.mean(measurements)
        if mean == 0:
            return None
        stdev = statistics.stdev(measurements) if len(measurements) > 1 else 0.0
        cv = stdev / mean if mean != 0 else 0.0

        # Check coefficient of variation
        if cv > self.CV_THRESHOLD:
            severity = min(1.0, cv / (self.CV_THRESHOLD * 2))
            return SCAAlert(
                alert_type=alert_type,
                severity=severity,
                details=f"High coefficient of variation: {cv:.3f} (threshold: {self.CV_THRESHOLD})",
            )

        # Check z-scores for outliers
        if stdev > 0:
            z_scores = [(x - mean) / stdev for x in measurements[-10:]]
            max_z = max(abs(z) for z in z_scores)
            if max_z > self.Z_SCORE_THRESHOLD:
                severity = min(1.0, max_z / (self.Z_SCORE_THRESHOLD * 2))
                return SCAAlert(
                    alert_type=alert_type,
                    severity=severity,
                    details=f"Outlier detected: z-score={max_z:.2f}",
                )

        return None

    def reset(self) -> None:
        """Reset measurements."""
        self._timing_measurements.clear()
        self._power_measurements.clear()
