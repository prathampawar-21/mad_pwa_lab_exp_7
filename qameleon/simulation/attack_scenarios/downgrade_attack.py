"""Downgrade attack simulation."""

from qameleon.simulation.mesh_simulator import MeshSimulator


def simulate_downgrade_attack(num_nodes: int = 5) -> dict:
    """Simulate downgrade attack scenario - should be detected."""
    sim = MeshSimulator(num_nodes)
    
    # Normal handshake
    sim.schedule(1.0, "HANDSHAKE", "node-0", "node-1")
    
    # Downgrade attempt
    sim.schedule(2.0, "ATTACK", "adversary", "node-0", {"type": "downgrade"})
    
    # Should trigger detection
    sim.schedule(2.1, "ATTACK", "adversary", "node-0", {"type": "downgrade_detected"})
    
    return sim.run(10.0)
