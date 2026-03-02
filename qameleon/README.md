# QAMELEON
**Quantum-Adaptive Military-Grade Encrypted Link & Operational Exchange for Networks**

[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![FIPS 203/204](https://img.shields.io/badge/FIPS-203%2F204-green.svg)](docs/protocol-specification.md)

## Overview

QAMELEON is a production-grade post-quantum cryptographic framework implementing NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA) standards with hybrid classical/post-quantum key exchange, classification-aware adaptive algorithm selection, and military-grade secure mesh networking.

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Mesh Network                  │
├─────────────────────────────────────────────────┤
│              Protocol (QHP)                     │
├──────────────┬──────────────────────────────────┤
│     CADE     │        Threat Intelligence       │
├──────────────┴──────────────────────────────────┤
│              Key Management                     │
├─────────────────────────────────────────────────┤
│             Crypto Primitives                   │
│  ML-KEM │ ML-DSA │ Hybrid │ Symmetric │ Hash   │
└─────────────────────────────────────────────────┘
```

## Quick Start

```bash
# Install
pip install -e ".[dev]"

# Run tests
make test

# Start dashboard
make dashboard

# Build C acceleration
make build-c
```

## Usage

```python
from qameleon.crypto_primitives.ml_kem import MLKEM
from qameleon.crypto_primitives.ml_dsa import MLDSA
from qameleon.crypto_primitives.hybrid_kem import HybridKEM

# ML-KEM key exchange
kem = MLKEM(security_level=768)
keypair = kem.keygen()
result = kem.encaps(keypair.public_key)
shared_secret = kem.decaps(keypair.secret_key, result.ciphertext)

# ML-DSA signing
dsa = MLDSA(security_level=65)
keys = dsa.keygen()
sig = dsa.sign(keys.secret_key, b"message")
assert dsa.verify(keys.public_key, b"message", sig)

# Hybrid KEM (post-quantum + classical)
hybrid = HybridKEM()
hkp = hybrid.keygen()
enc = hybrid.encaps(hkp.public_key)
ss = hybrid.decaps(hkp.secret_key, enc)
```

## Testing

```bash
make test-unit        # Unit tests
make test-security    # Security tests
make coverage         # Coverage report
```

## Documentation

- [Architecture](docs/architecture.md)
- [Protocol Specification](docs/protocol-specification.md)
- [Threat Model](docs/threat-model.md)
- [Deployment Guide](docs/deployment-guide.md)
- [API Reference](docs/api-reference.md)
