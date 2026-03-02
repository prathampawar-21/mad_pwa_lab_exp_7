"""Energy benchmark (estimated)."""

from qameleon.cade.cost_model import CostModel
from qameleon.cade.device_profiler import DeviceProfiler


def run_energy_benchmark() -> dict:
    """Estimate energy consumption for different device profiles."""
    devices = {
        "high_performance": DeviceProfiler.high_performance(),
        "mobile": DeviceProfiler.mobile(),
        "iot": DeviceProfiler.constrained_iot(),
    }
    algorithms = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]
    results = {}
    for device_name, device in devices.items():
        results[device_name] = {}
        for algo in algorithms:
            cost = CostModel.estimate(algo, device)
            results[device_name][algo] = {
                "energy_mj": cost.energy_mj,
                "latency_ms": cost.latency_ms,
            }
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_energy_benchmark(), indent=2))
