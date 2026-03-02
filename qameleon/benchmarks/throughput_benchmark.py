"""Throughput benchmark."""

import time
from qameleon.crypto_primitives.symmetric import SymmetricCipher


def run_throughput_benchmark(data_size: int = 1024 * 1024, duration: float = 5.0) -> dict:
    """Measure encryption throughput in MB/s."""
    key = SymmetricCipher.generate_key()
    data = b"x" * data_size
    
    count = 0
    start = time.perf_counter()
    while time.perf_counter() - start < duration:
        SymmetricCipher.encrypt(key, data)
        count += 1
    elapsed = time.perf_counter() - start
    
    throughput_mbps = (count * data_size) / (elapsed * 1024 * 1024)
    return {
        "operations": count,
        "elapsed_s": elapsed,
        "throughput_mbps": throughput_mbps,
        "data_size_bytes": data_size,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run_throughput_benchmark(), indent=2))
