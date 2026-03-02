"""Run all benchmarks and output results."""

import json
import sys
from benchmarks.latency_benchmark import run_kem_latency_benchmark
from benchmarks.throughput_benchmark import run_throughput_benchmark
from benchmarks.energy_benchmark import run_energy_benchmark
from benchmarks.memory_benchmark import run_memory_benchmark
from benchmarks.scalability_benchmark import run_scalability_benchmark


def run_all() -> dict:
    """Run all benchmarks."""
    results = {}
    print("Running latency benchmarks...")
    results["latency"] = run_kem_latency_benchmark()
    print("Running throughput benchmarks...")
    results["throughput"] = run_throughput_benchmark(duration=2.0)
    print("Running energy benchmarks...")
    results["energy"] = run_energy_benchmark()
    print("Running memory benchmarks...")
    results["memory"] = run_memory_benchmark()
    print("Running scalability benchmarks...")
    results["scalability"] = run_scalability_benchmark()
    return results


if __name__ == "__main__":
    results = run_all()
    print("\n=== QAMELEON Benchmark Results ===")
    print(json.dumps(results, indent=2))
