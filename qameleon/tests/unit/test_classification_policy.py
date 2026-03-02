"""Unit tests for classification policy."""
import pytest
from qameleon.cade.classification_policy import ClassificationLevel, ClassificationPolicy
from qameleon.exceptions import PolicyViolationError


@pytest.mark.unit
class TestClassificationPolicy:
    def test_get_requirements(self):
        req = ClassificationPolicy.get_requirements(ClassificationLevel.SECRET)
        assert req.require_hybrid is True
        assert req.require_forward_secrecy is True

    def test_valid_kem(self):
        ClassificationPolicy.validate_kem(ClassificationLevel.UNCLASSIFIED, "ML-KEM-768")

    def test_invalid_kem_raises(self):
        with pytest.raises(PolicyViolationError):
            ClassificationPolicy.validate_kem(ClassificationLevel.TOP_SECRET, "ML-KEM-512")

    def test_cross_domain_write_down_raises(self):
        with pytest.raises(PolicyViolationError):
            ClassificationPolicy.validate_cross_domain(
                ClassificationLevel.SECRET, ClassificationLevel.UNCLASSIFIED
            )

    def test_negotiate_takes_higher(self):
        level = ClassificationPolicy.negotiate_session_level(
            ClassificationLevel.CONFIDENTIAL, ClassificationLevel.SECRET
        )
        assert level == ClassificationLevel.SECRET
