"""Unit tests for monotonic upgrade enforcer."""
import pytest
from qameleon.protocol.monotonic_upgrade import MonotonicUpgradeEnforcer, CryptoParameters
from qameleon.exceptions import DowngradeAttemptError


@pytest.mark.unit
class TestMonotonicUpgrade:
    def test_valid_upgrade(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(512, 44, 128, 0))
        enforcer.validate_upgrade(CryptoParameters(768, 65, 256, 1))

    def test_same_level_allowed(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(768, 65, 256, 1))
        enforcer.validate_upgrade(CryptoParameters(768, 65, 256, 1))

    def test_kem_downgrade_raises(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(768, 65, 256, 1))
        with pytest.raises(DowngradeAttemptError):
            enforcer.validate_upgrade(CryptoParameters(512, 65, 256, 1))

    def test_sig_downgrade_raises(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(768, 65, 256, 1))
        with pytest.raises(DowngradeAttemptError):
            enforcer.validate_upgrade(CryptoParameters(768, 44, 256, 1))

    def test_symmetric_downgrade_raises(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(768, 65, 256, 1))
        with pytest.raises(DowngradeAttemptError):
            enforcer.validate_upgrade(CryptoParameters(768, 65, 128, 1))
