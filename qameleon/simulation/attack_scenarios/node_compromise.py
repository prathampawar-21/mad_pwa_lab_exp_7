"""Node compromise attack simulation."""

from qameleon.simulation.mesh_simulator import MeshSimulator


def simulate_node_compromise(num_nodes: int = 10, compromised_fraction: float = 0.2) -> dict:
    """Simulate node compromise scenario."""
    sim = MeshSimulator(num_nodes)
    num_compromised = int(num_nodes * compromised_fraction)
    
    for i in range(num_compromised):
        sim.schedule(5.0, "ATTACK", f"node-{i}", "network", {"type": "compromise"})
    
    return sim.run(50.0)
