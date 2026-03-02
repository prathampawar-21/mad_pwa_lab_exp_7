# QAMELEON Project Structure

## File Tree

```
qameleon/
├── src/qameleon/          # Core library
│   ├── crypto_primitives/ # Layer 1: Cryptographic building blocks
│   ├── key_management/    # Layer 2: Key lifecycle management
│   ├── protocol/          # Layer 3: QHP protocol implementation
│   ├── cade/              # Layer 4: Classification-Aware Decision Engine
│   ├── threat_intel/      # Layer 5: Threat intelligence
│   ├── dashboard/         # Layer 6: Management dashboard
│   └── mesh_network/      # Layer 7: Secure mesh networking
├── tests/                 # Test suite
├── formal_verification/   # Tamarin/ProVerif models
├── simulation/            # Attack and battlefield simulation
├── benchmarks/            # Performance benchmarks
└── docs/                  # Documentation
```

## Build Commands

- `make setup` - Install dependencies
- `make test` - Run all tests
- `make build-c` - Compile C acceleration libraries
- `make dashboard` - Start management dashboard
- `make lint` - Run linters
- `make format` - Format code

## Architecture Dependency Graph

```
mesh_network → protocol → key_management → crypto_primitives
     ↓              ↓
dashboard      threat_intel → cade
```

## Performance Tiers

| Tier | Algorithm | Latency | Use Case |
|------|-----------|---------|----------|
| 1 | ML-KEM-512 | ~0.5ms | IoT/constrained |
| 2 | ML-KEM-768 | ~0.8ms | Standard |
| 3 | ML-KEM-1024 | ~1.2ms | High security |
