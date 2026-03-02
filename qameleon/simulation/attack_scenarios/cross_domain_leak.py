"""Cross-domain information leak simulation."""

from qameleon.simulation.mesh_simulator import MeshSimulator


def simulate_cross_domain_leak(num_domains: int = 3) -> dict:
    """Simulate cross-domain leak attempt - should be blocked."""
    sim = MeshSimulator(num_domains * 3)
    
    for d in range(num_domains):
        sim.schedule(float(d), "ATTACK", f"domain-{d}", f"domain-{(d-1)%num_domains}",
                     {"type": "write_down"})
    
    return sim.run(20.0)
