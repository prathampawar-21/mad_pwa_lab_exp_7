"""Quantum harvest-now-decrypt-later attack simulation."""

from qameleon.simulation.mesh_simulator import MeshSimulator


def simulate_quantum_harvest(num_nodes: int = 10, duration: float = 100.0) -> dict:
    """Simulate harvest-now-decrypt-later attack scenario."""
    sim = MeshSimulator(num_nodes)
    
    # Schedule normal traffic
    for i in range(num_nodes):
        sim.schedule(float(i), "HANDSHAKE", f"node-{i}", f"node-{(i+1)%num_nodes}")
    
    # Schedule harvest attack
    sim.schedule(10.0, "ATTACK", "quantum-adversary", "network", {"type": "harvest"})
    
    return sim.run(duration)
