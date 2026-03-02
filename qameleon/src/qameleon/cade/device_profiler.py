"""Device profiler for hardware capability detection."""

from qameleon.cade.cost_model import DeviceCapability


class DeviceProfiler:
    """Creates DeviceCapability profiles from hardware specs."""

    @staticmethod
    def from_manual(
        cpu_frequency_mhz: float,
        available_ram_kb: float,
        battery_mah: float,
        network_bandwidth_kbps: float = 1000.0,
        has_hardware_crypto: bool = False,
        device_name: str = "Manual",
    ) -> DeviceCapability:
        """Create DeviceCapability from manually specified hardware specs."""
        return DeviceCapability(
            cpu_frequency_mhz=cpu_frequency_mhz,
            available_ram_kb=available_ram_kb,
            battery_mah=battery_mah,
            network_bandwidth_kbps=network_bandwidth_kbps,
            has_hardware_crypto=has_hardware_crypto,
            device_name=device_name,
        )

    @staticmethod
    def high_performance() -> DeviceCapability:
        """Profile for high-performance server/workstation."""
        return DeviceCapability(
            cpu_frequency_mhz=3000.0,
            available_ram_kb=8 * 1024 * 1024,
            battery_mah=0.0,
            network_bandwidth_kbps=1_000_000,
            has_hardware_crypto=True,
            device_name="High Performance",
        )

    @staticmethod
    def mobile() -> DeviceCapability:
        """Profile for mobile device."""
        return DeviceCapability(
            cpu_frequency_mhz=1500.0,
            available_ram_kb=512 * 1024,
            battery_mah=3000.0,
            network_bandwidth_kbps=50_000,
            has_hardware_crypto=False,
            device_name="Mobile",
        )

    @staticmethod
    def constrained_iot() -> DeviceCapability:
        """Profile for constrained IoT device."""
        return DeviceCapability(
            cpu_frequency_mhz=80.0,
            available_ram_kb=256,
            battery_mah=1000.0,
            network_bandwidth_kbps=250,
            has_hardware_crypto=False,
            device_name="Constrained IoT",
        )
