"""Convoy movement secure communication simulation."""

from qameleon.simulation.mesh_simulator import MeshSimulator


def simulate_convoy(num_vehicles: int = 10, duration: float = 300.0) -> dict:
    """Simulate convoy movement with dynamic mesh topology."""
    sim = MeshSimulator(num_vehicles)
    
    # Initial handshakes
    for i in range(num_vehicles - 1):
        sim.schedule(float(i) * 0.5, "HANDSHAKE", f"vehicle-{i}", f"vehicle-{i+1}")
    
    # Regular message traffic
    for t in range(0, int(duration), 10):
        for i in range(num_vehicles):
            sim.schedule(float(t), "MESSAGE", f"vehicle-{i}", "command",
                        {"type": "position_report"})
    
    # Rekey events
    for t in range(60, int(duration), 60):
        for i in range(num_vehicles):
            sim.schedule(float(t), "REKEY", f"vehicle-{i}", f"vehicle-{(i+1)%num_vehicles}")
    
    return sim.run(duration)
