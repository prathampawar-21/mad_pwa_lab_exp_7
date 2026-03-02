"""Integration test: adaptive rekey flow."""
import pytest
from qameleon.protocol.adaptive_rekey import AdaptiveRekeyManager, RekeyTrigger
from qameleon.protocol.session import SecureSession
from qameleon.crypto_primitives.key_combiner import KeyCombiner


@pytest.mark.integration
class TestAdaptiveRekeyFlow:
    def test_threat_escalation_triggers_rekey(self):
        mgr = AdaptiveRekeyManager(RekeyTrigger(threat_threshold=0.5))
        mgr.initialize()

        master = b"m" * 64
        session = SecureSession(master, "test-session")

        # Escalate threat
        mgr.update_threat_score(0.8)
        needed, reason = mgr.check_rekey_needed()
        assert needed

        # Perform rekey
        new_master = KeyCombiner.derive_session_key(master, "rekey", 64)
        session.update_key(new_master)
        mgr.perform_rekey()

        # Session continues working
        payload = session.encrypt(b"still working")
        data = session.decrypt(payload)
        assert data == b"still working"

        # No more rekey needed
        needed, _ = mgr.check_rekey_needed()
        assert not needed
