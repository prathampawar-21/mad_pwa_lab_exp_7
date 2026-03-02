# QAMELEON Architecture

## Overview

QAMELEON is a layered post-quantum cryptographic framework with 7 layers:

## Layer Architecture

```
Layer 7: Mesh Network
Layer 6: Dashboard
Layer 5: Threat Intelligence
Layer 4: CADE (Classification-Aware Decision Engine)
Layer 3: Protocol (QHP)
Layer 2: Key Management
Layer 1: Crypto Primitives
```

## Crypto Primitives (Layer 1)

- **ML-KEM** (FIPS 203): Lattice-based key encapsulation
- **ML-DSA** (FIPS 204): Lattice-based digital signatures
- **Hybrid KEM**: ML-KEM + X25519 for defense-in-depth
- **Hybrid Auth**: ML-DSA + Ed25519 for composite signatures
- **AES-256-GCM**: Symmetric authenticated encryption
- **SHA3 family**: Cryptographic hash functions

## Key Management (Layer 2)

- Thread-safe KeyStore with lifecycle states
- Persistent encrypted storage (PBKDF2 + AES-GCM)
- Merkle tree key authentication
- Shamir's Secret Sharing for key backup
- Hash-chained audit logging

## Protocol (Layer 3)

The QHP (QAMELEON Handshake Protocol) operates in 4 phases:
1. **HELLO**: Identity + key exchange parameters
2. **HELLO_RESPONSE**: Mutual parameter negotiation
3. **KEY_INIT**: Encapsulation + nonce binding
4. **KEY_RESPONSE**: Confirmation + session establishment

## CADE (Layer 4)

Classification-Aware Decision Engine selects optimal algorithms based on:
- Classification level requirements
- Device hardware capabilities
- Current threat level
- Mission priority

## Threat Intelligence (Layer 5)

- SCA detector (timing/power analysis)
- Network IDS (replay, brute force, rate limiting)
- Quantum threat estimator
- Unified threat score (UTS)
