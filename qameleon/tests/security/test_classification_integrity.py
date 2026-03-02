"""Security test: classification integrity."""
import pytest
from qameleon.key_management.cross_domain_gateway import CrossDomainGateway, ClassificationLevel
from qameleon.crypto_primitives.key_combiner import KeyCombiner
from qameleon.exceptions import ClassificationViolationError


@pytest.mark.security
class TestClassificationIntegrity:
    @pytest.mark.parametrize("source,target", [
        (ClassificationLevel.CONFIDENTIAL, ClassificationLevel.UNCLASSIFIED),
        (ClassificationLevel.SECRET, ClassificationLevel.CONFIDENTIAL),
        (ClassificationLevel.TOP_SECRET, ClassificationLevel.SECRET),
        (ClassificationLevel.TOP_SECRET_SCI, ClassificationLevel.TOP_SECRET),
    ])
    def test_write_down_all_pairs(self, source, target):
        gw = CrossDomainGateway()
        with pytest.raises(ClassificationViolationError):
            gw.create_session(source, target)

    def test_classification_bound_in_key(self):
        k1 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32, classification_level=1)
        k2 = KeyCombiner.combine(b"a"*32, b"b"*32, b"c"*32, b"d"*32, classification_level=2)
        assert k1 != k2
