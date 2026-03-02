# QAMELEON Deployment Guide

## Requirements

- Python 3.12+
- gcc (for C acceleration)
- Optional: Docker

## Installation

```bash
# Clone and install
pip install -e ".[dev]"

# Build C acceleration (optional but recommended)
make build-c

# Verify C acceleration
make check-c
```

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
QAMELEON_DEFAULT_KEM=ML-KEM-768
QAMELEON_DEFAULT_SIG=ML-DSA-65
QAMELEON_QUANTUM_THREAT=0.1
```

## Docker Deployment

```bash
docker-compose up -d
```

## Dashboard

```bash
make dashboard
# Navigate to http://localhost:8000
```

## Security Checklist

- [ ] Change default API keys
- [ ] Configure appropriate classification level
- [ ] Enable TLS for dashboard
- [ ] Set up audit log retention
- [ ] Configure threat thresholds
