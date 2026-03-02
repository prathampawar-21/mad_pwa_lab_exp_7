"""Integration test: cross-domain key management."""
import pytest
from qameleon.key_management.cd_kms import CrossDomainKMS
from qameleon.key_management.cross_domain_gateway import CrossDomainGateway, ClassificationLevel
from qameleon.exceptions import ClassificationViolationError


@pytest.mark.integration
class TestCrossDomain:
    def test_kms_generate_rotate_revoke(self):
        kms = CrossDomainKMS()
        key = kms.generate_key("k1", classification_level=2)
        assert len(key) == 32
        new_key = kms.rotate_key("k1", "k2")
        assert len(new_key) == 32
        kms.revoke_key("k2")

    def test_backup_recover(self):
        kms = CrossDomainKMS()
        key = kms.generate_key("backup_k")
        shares = kms.backup_key("backup_k", k=2, n=3)
        assert len(shares) == 3
        recovered_key = kms.recover_key("backup_k_r", shares[:2], classification_level=0)
        assert recovered_key == key

    def test_gateway_write_down_denied(self):
        gw = CrossDomainGateway()
        with pytest.raises(ClassificationViolationError):
            gw.create_session(ClassificationLevel.SECRET, ClassificationLevel.UNCLASSIFIED)

    def test_gateway_write_up_allowed(self):
        gw = CrossDomainGateway()
        session = gw.create_session(ClassificationLevel.CONFIDENTIAL, ClassificationLevel.SECRET)
        assert session is not None
