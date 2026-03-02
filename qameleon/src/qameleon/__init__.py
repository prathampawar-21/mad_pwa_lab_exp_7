"""QAMELEON: Quantum-Adaptive Military-Grade Encrypted Link & Operational Exchange for Networks."""

__version__ = "1.0.0"
__author__ = "QAMELEON Project"

from qameleon.crypto_primitives.ml_kem import MLKEM, MLKEMKeyPair, MLKEMEncapsResult
from qameleon.crypto_primitives.ml_dsa import MLDSA, MLDSAKeyPair
from qameleon.crypto_primitives.hybrid_kem import HybridKEM, HybridKEMKeyPair, HybridEncapsResult
from qameleon.crypto_primitives.hybrid_auth import HybridAuthenticator, HybridSigningKeyPair
from qameleon.exceptions import QAMELEONError

__all__ = [
    "__version__",
    "MLKEM",
    "MLKEMKeyPair",
    "MLKEMEncapsResult",
    "MLDSA",
    "MLDSAKeyPair",
    "HybridKEM",
    "HybridKEMKeyPair",
    "HybridEncapsResult",
    "HybridAuthenticator",
    "HybridSigningKeyPair",
    "QAMELEONError",
]
