"""Coalition operations cross-domain secure communication."""

from simulation.mesh_simulator import MeshSimulator


def simulate_coalition_ops(num_partners: int = 3, duration: float = 200.0) -> dict:
    """Simulate coalition operations with different classification levels."""
    sim = MeshSimulator(num_partners * 5)
    
    # Cross-domain handshakes (write-up only)
    for i in range(num_partners):
        for j in range(i, num_partners):
            if i != j:
                sim.schedule(float(i + j), "HANDSHAKE",
                            f"partner-{i}-node-0", f"partner-{j}-node-0")
    
    # Data exchange
    for t in range(10, int(duration), 15):
        for i in range(num_partners):
            sim.schedule(float(t), "MESSAGE",
                        f"partner-{i}-node-0", f"partner-{(i+1)%num_partners}-node-0")
    
    return sim.run(duration)
