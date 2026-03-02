# QHP Protocol Specification

## Overview

The QAMELEON Handshake Protocol (QHP) provides mutual authentication and
post-quantum secure key exchange for mesh networks.

## Protocol Flow

```
Initiator                    Responder
    |                             |
    |------ HELLO --------------->|
    |<----- HELLO_RESPONSE -------|
    |------ KEY_INIT ------------->|
    |<----- KEY_RESPONSE ---------|
    |                             |
    |=== Secure Session =========|
```

## Message Types

- **HELLO**: Node identity, KEM/sig public keys, supported algorithms
- **HELLO_RESPONSE**: Responder identity, selected algorithms
- **KEY_INIT**: KEM ciphertext, initiator nonce
- **KEY_RESPONSE**: Confirmation HMAC, responder nonce

## Security Properties

1. **Mutual Authentication**: Both parties sign all messages
2. **Post-Quantum KE**: ML-KEM-768+ provides quantum-resistant shared secret
3. **Forward Secrecy**: Ephemeral KEM keys ensure PFS
4. **Replay Prevention**: Nonce tracking with 5-minute window
5. **Downgrade Resistance**: MonotonicUpgradeEnforcer prevents rollback
6. **Classification Binding**: Session keys bound to classification level

## Key Derivation

```
Master Key = HKDF(classical_ss || pq_ss, nonce_a || nonce_b,
                  info="QAMELEON-MASTER-KEY-v1|class=N")
```
