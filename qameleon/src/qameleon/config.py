"""QAMELEON configuration loaded from environment variables."""

import os
from dataclasses import dataclass, field


@dataclass
class QAMELEONConfig:
    """Central configuration for QAMELEON framework."""

    log_level: str = field(default_factory=lambda: os.environ.get("QAMELEON_LOG_LEVEL", "INFO"))
    log_format: str = field(default_factory=lambda: os.environ.get("QAMELEON_LOG_FORMAT", "json"))
    default_kem: str = field(
        default_factory=lambda: os.environ.get("QAMELEON_DEFAULT_KEM", "ML-KEM-768")
    )
    default_sig: str = field(
        default_factory=lambda: os.environ.get("QAMELEON_DEFAULT_SIG", "ML-DSA-65")
    )
    quantum_threat: float = field(
        default_factory=lambda: float(os.environ.get("QAMELEON_QUANTUM_THREAT", "0.1"))
    )
    threat_threshold: float = field(
        default_factory=lambda: float(os.environ.get("QAMELEON_THREAT_THRESHOLD", "0.7"))
    )
    dashboard_host: str = field(
        default_factory=lambda: os.environ.get("QAMELEON_DASHBOARD_HOST", "0.0.0.0")
    )
    dashboard_port: int = field(
        default_factory=lambda: int(os.environ.get("QAMELEON_DASHBOARD_PORT", "8000"))
    )
    dashboard_auth: bool = field(
        default_factory=lambda: os.environ.get("QAMELEON_DASHBOARD_AUTH", "true").lower() == "true"
    )
    sca_protection: bool = field(
        default_factory=lambda: os.environ.get("QAMELEON_SCA_PROTECTION", "true").lower() == "true"
    )

    @classmethod
    def from_env(cls) -> "QAMELEONConfig":
        """Create configuration from environment variables."""
        return cls()


# Global default configuration instance
default_config = QAMELEONConfig()
