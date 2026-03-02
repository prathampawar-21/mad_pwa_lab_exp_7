"""Security test: downgrade resistance."""
import pytest
from qameleon.protocol.monotonic_upgrade import MonotonicUpgradeEnforcer, CryptoParameters
from qameleon.exceptions import DowngradeAttemptError


@pytest.mark.security
class TestDowngradeResistance:
    @pytest.mark.parametrize("field,old,new", [
        ("kem_level", 768, 512),
        ("sig_level", 65, 44),
        ("symmetric_bits", 256, 128),
        ("sca_level", 2, 1),
    ])
    def test_downgrade_raises(self, field, old, new):
        enforcer = MonotonicUpgradeEnforcer()
        baseline = CryptoParameters(768, 65, 256, 2)
        enforcer.set_baseline(baseline)
        params = {
            "kem_level": 768, "sig_level": 65, "symmetric_bits": 256, "sca_level": 2
        }
        params[field] = new
        with pytest.raises(DowngradeAttemptError):
            enforcer.validate_upgrade(CryptoParameters(**params))

    def test_upgrade_allowed(self):
        enforcer = MonotonicUpgradeEnforcer()
        enforcer.set_baseline(CryptoParameters(512, 44, 128, 0))
        enforcer.validate_upgrade(CryptoParameters(1024, 87, 256, 3))
