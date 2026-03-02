"""Memory usage benchmark."""

import tracemalloc
from qameleon.crypto_primitives.ml_kem import MLKEM


def measure_memory(operation, *args) -> dict:
    """Measure peak memory usage of an operation."""
    tracemalloc.start()
    operation(*args)
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {"current_bytes": current, "peak_bytes": peak, "peak_kb": peak / 1024}


def run_memory_benchmark() -> dict:
    """Run memory benchmarks for all KEM levels."""
    results = {}
    for level in [512, 768, 1024]:
        kem = MLKEM(level)
        kp = kem.keygen()
        results[f"ML-KEM-{level}"] = {
            "keygen": measure_memory(kem.keygen),
            "encaps": measure_memory(kem.encaps, kp.public_key),
        }
    return results


if __name__ == "__main__":
    import json
    print(json.dumps(run_memory_benchmark(), indent=2))
