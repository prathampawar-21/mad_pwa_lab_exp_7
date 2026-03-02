"""Latency benchmark for crypto operations."""

import time
from typing import Callable


def measure_latency(operation: Callable, iterations: int = 100) -> dict:
    """Measure operation latency statistics."""
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        end = time.perf_counter()
        times.append((end - start) * 1000)  # ms
    
    times.sort()
    return {
        "min_ms": times[0],
        "max_ms": times[-1],
        "mean_ms": sum(times) / len(times),
        "p50_ms": times[len(times) // 2],
        "p99_ms": times[int(len(times) * 0.99)],
        "iterations": iterations,
    }


def run_kem_latency_benchmark():
    """Run KEM latency benchmarks."""
    from qameleon.crypto_primitives.ml_kem import MLKEM
    results = {}
    for level in [512, 768, 1024]:
        kem = MLKEM(level)
        kp = kem.keygen()
        results[f"ML-KEM-{level}"] = {
            "keygen": measure_latency(kem.keygen, 50),
            "encaps": measure_latency(lambda: kem.encaps(kp.public_key), 50),
        }
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_kem_latency_benchmark(), indent=2))
