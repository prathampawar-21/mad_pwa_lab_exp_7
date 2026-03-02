# QAMELEON Threat Model

## Adversary Capabilities

### Classical Adversary
- Passive eavesdropping
- Active MITM
- Replay attacks
- Downgrade attacks

### Quantum Adversary
- Shor's algorithm breaking RSA/ECC
- Grover's algorithm halving symmetric key strength
- Harvest-now-decrypt-later attacks

### Physical Adversary
- Side-channel attacks (timing, power)
- Node compromise
- Physical key extraction

## Mitigations

| Threat | Mitigation |
|--------|-----------|
| Quantum attacks | ML-KEM + ML-DSA (FIPS 203/204) |
| Classical MITM | Hybrid KEM/auth + mutual authentication |
| Replay attacks | Nonce tracking, timestamp verification |
| Downgrade | MonotonicUpgradeEnforcer |
| Write-down | CrossDomainGateway enforcement |
| Key compromise | Forward secrecy, periodic rekeying |
| SCA | Constant-time ops, random delays, masking |
