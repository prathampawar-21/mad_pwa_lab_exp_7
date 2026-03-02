"""Unit tests for SCA protections."""
import pytest
from qameleon.crypto_primitives.sca_protected import (
    constant_time_compare, mask_value, unmask_value, SCAProtectedOperation,
)


@pytest.mark.unit
class TestSCAProtected:
    def test_constant_time_compare_equal(self):
        assert constant_time_compare(b"abc", b"abc") is True

    def test_constant_time_compare_unequal(self):
        assert constant_time_compare(b"abc", b"def") is False

    def test_mask_unmask(self):
        original = b"secret data"
        masked, mask = mask_value(original)
        assert masked != original
        recovered = unmask_value(masked, mask)
        assert recovered == original

    def test_sca_op_runs(self):
        op = SCAProtectedOperation(enable_random_delay=False)
        result = op.run(lambda: 42)
        assert result == 42
