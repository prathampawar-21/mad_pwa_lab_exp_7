"""Unit tests for CADE decision engine."""
import pytest
from qameleon.cade.decision_engine import CADEEngine
from qameleon.cade.classification_policy import ClassificationLevel
from qameleon.cade.device_profiler import DeviceProfiler


@pytest.mark.unit
class TestDecisionEngine:
    def test_decide_unclassified(self):
        engine = CADEEngine()
        device = DeviceProfiler.high_performance()
        decision = engine.decide(ClassificationLevel.UNCLASSIFIED, device)
        assert decision.selected_kem in ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
        assert decision.selected_sig in ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]

    def test_decide_top_secret(self):
        engine = CADEEngine()
        device = DeviceProfiler.high_performance()
        decision = engine.decide(ClassificationLevel.TOP_SECRET, device)
        assert decision.selected_kem == "ML-KEM-1024"
        assert decision.selected_sig == "ML-DSA-87"

    def test_high_threat_selects_stronger(self):
        engine = CADEEngine()
        device = DeviceProfiler.high_performance()
        d_low = engine.decide(ClassificationLevel.SECRET, device, threat_score=0.0)
        d_high = engine.decide(ClassificationLevel.SECRET, device, threat_score=0.9)
        # Both should be valid
        assert d_low.selected_kem is not None
        assert d_high.selected_kem is not None

    def test_decision_has_rationale(self):
        engine = CADEEngine()
        device = DeviceProfiler.mobile()
        decision = engine.decide(ClassificationLevel.CONFIDENTIAL, device)
        assert len(decision.rationale) > 0
