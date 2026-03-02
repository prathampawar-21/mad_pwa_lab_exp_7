"""Unit tests for algorithm registry."""
import pytest
from qameleon.cade.algorithm_registry import AlgorithmRegistry


@pytest.mark.unit
class TestAlgorithmRegistry:
    def test_get_ml_kem_768(self):
        profile = AlgorithmRegistry.get("ML-KEM-768")
        assert profile.nist_level == 3
        assert profile.category == "KEM"

    def test_get_ml_dsa_65(self):
        profile = AlgorithmRegistry.get("ML-DSA-65")
        assert profile.nist_level == 3
        assert profile.category == "SIG"

    def test_list_kem(self):
        kems = AlgorithmRegistry.list_kem()
        assert "ML-KEM-768" in kems
        assert "ML-DSA-65" not in kems

    def test_list_sig(self):
        sigs = AlgorithmRegistry.list_sig()
        assert "ML-DSA-65" in sigs

    def test_unknown_raises(self):
        with pytest.raises(KeyError):
            AlgorithmRegistry.get("UNKNOWN-ALG")
