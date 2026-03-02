"""Scalability benchmark."""

import time
from qameleon.mesh_network.mesh_router import MeshRouter


def run_scalability_benchmark(max_nodes: int = 100) -> dict:
    """Test routing scalability with increasing node counts."""
    results = []
    for n in [10, 25, 50, 100]:
        if n > max_nodes:
            break
        router = MeshRouter("local")
        for i in range(n):
            router.add_route(f"node-{i}", f"hop-{i%5}", i%5+1)
        
        start = time.perf_counter()
        for i in range(n):
            router.find_route(f"node-{i}")
        elapsed = time.perf_counter() - start
        
        results.append({
            "nodes": n,
            "lookup_time_ms": elapsed * 1000,
            "lookups_per_sec": n / elapsed if elapsed > 0 else 0,
        })
    return {"scalability": results}


if __name__ == "__main__":
    import json
    print(json.dumps(run_scalability_benchmark(), indent=2))
