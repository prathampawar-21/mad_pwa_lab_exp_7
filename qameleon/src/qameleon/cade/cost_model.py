"""Cost model estimating algorithm performance on specific hardware."""

from dataclasses import dataclass
from typing import Optional

from qameleon.cade.algorithm_registry import AlgorithmProfile, AlgorithmRegistry


@dataclass
class DeviceCapability:
    """Hardware capability profile."""
    cpu_frequency_mhz: float
    available_ram_kb: float
    battery_mah: float
    network_bandwidth_kbps: float
    has_hardware_crypto: bool = False
    device_name: str = "Generic"


@dataclass
class AlgorithmCost:
    """Estimated cost of an algorithm operation."""
    algorithm: str
    latency_ms: float
    energy_mj: float
    bandwidth_bytes: int
    memory_kb: int


class CostModel:
    """Estimates algorithm costs on a specific device."""

    BASE_CPU_MHZ = 1000.0  # Reference CPU frequency

    @classmethod
    def estimate(cls, algorithm_name: str, device: DeviceCapability) -> AlgorithmCost:
        """Estimate operation cost for an algorithm on a device."""
        profile = AlgorithmRegistry.get(algorithm_name)

        # Latency: scale by CPU frequency ratio
        cpu_ratio = cls.BASE_CPU_MHZ / device.cpu_frequency_mhz
        base_latency_ms = profile.operation_cycles / (cls.BASE_CPU_MHZ * 1000)
        latency_ms = base_latency_ms * cpu_ratio

        if device.has_hardware_crypto:
            latency_ms *= 0.3  # 3x speedup with hardware

        # Energy: proportional to cycles and inversely to frequency
        power_mw = 100.0 * (device.cpu_frequency_mhz / cls.BASE_CPU_MHZ)
        energy_mj = latency_ms * power_mw / 1000.0

        # Bandwidth
        bandwidth_bytes = profile.public_key_bytes + profile.ciphertext_bytes

        return AlgorithmCost(
            algorithm=algorithm_name,
            latency_ms=latency_ms,
            energy_mj=energy_mj,
            bandwidth_bytes=bandwidth_bytes,
            memory_kb=profile.memory_kb,
        )

    @classmethod
    def fits_device(cls, algorithm_name: str, device: DeviceCapability) -> bool:
        """Check if an algorithm can run on a device."""
        cost = cls.estimate(algorithm_name, device)
        return cost.memory_kb <= device.available_ram_kb
