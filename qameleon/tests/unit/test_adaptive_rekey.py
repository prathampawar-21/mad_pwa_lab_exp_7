"""Unit tests for adaptive rekey manager."""
import pytest
from qameleon.protocol.adaptive_rekey import AdaptiveRekeyManager, RekeyTrigger


@pytest.mark.unit
class TestAdaptiveRekey:
    def test_no_rekey_initially(self):
        mgr = AdaptiveRekeyManager()
        mgr.initialize()
        needed, reason = mgr.check_rekey_needed()
        assert not needed

    def test_threat_triggers_rekey(self):
        mgr = AdaptiveRekeyManager(RekeyTrigger(threat_threshold=0.5))
        mgr.initialize()
        mgr.update_threat_score(0.8)
        needed, reason = mgr.check_rekey_needed()
        assert needed
        assert "threat" in reason

    def test_message_count_triggers_rekey(self):
        mgr = AdaptiveRekeyManager(RekeyTrigger(max_messages=5))
        mgr.initialize()
        for _ in range(6):
            mgr.record_message(100)
        needed, _ = mgr.check_rekey_needed()
        assert needed

    def test_perform_rekey_resets_counter(self):
        mgr = AdaptiveRekeyManager(RekeyTrigger(max_messages=5))
        mgr.initialize()
        for _ in range(6):
            mgr.record_message(100)
        mgr.perform_rekey()
        needed, _ = mgr.check_rekey_needed()
        assert not needed
