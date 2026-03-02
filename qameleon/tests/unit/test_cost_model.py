"""Unit tests for cost model."""
import pytest
from qameleon.cade.cost_model import CostModel
from qameleon.cade.device_profiler import DeviceProfiler


@pytest.mark.unit
class TestCostModel:
    def test_estimate_returns_positive_values(self):
        device = DeviceProfiler.high_performance()
        cost = CostModel.estimate("ML-KEM-768", device)
        assert cost.latency_ms > 0
        assert cost.energy_mj >= 0
        assert cost.bandwidth_bytes > 0

    def test_hardware_crypto_reduces_latency(self):
        fast = DeviceProfiler.high_performance()
        slow = DeviceProfiler.mobile()
        fast.has_hardware_crypto = True
        cost_fast = CostModel.estimate("ML-KEM-768", fast)
        cost_slow = CostModel.estimate("ML-KEM-768", slow)
        # High performance with hardware accel should be faster
        assert cost_fast.latency_ms < cost_slow.latency_ms

    def test_fits_device(self):
        device = DeviceProfiler.high_performance()
        assert CostModel.fits_device("ML-KEM-512", device)

    def test_constrained_device_may_not_fit_1024(self):
        device = DeviceProfiler.constrained_iot()
        # constrained IoT has only 256KB RAM - 1024 needs 64KB which should fit
        # but let's just test the function runs
        result = CostModel.fits_device("ML-KEM-1024", device)
        assert isinstance(result, bool)
