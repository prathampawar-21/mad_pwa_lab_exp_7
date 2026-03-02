"""Integration test: mesh network discovery and routing."""
import pytest
from qameleon.mesh_network.mesh_node import MeshNode
from qameleon.mesh_network.node_discovery import DiscoveryBeacon
from qameleon.mesh_network.mesh_router import MeshRouter


@pytest.mark.integration
class TestMeshNetwork:
    def test_beacon_discovery(self):
        node_a = MeshNode("node-a")
        node_b = MeshNode("node-b")
        node_a.initialize()
        node_b.initialize()

        beacon_b = node_b.create_beacon()
        is_new = node_a.process_beacon(beacon_b)
        assert is_new

    def test_routing(self):
        router = MeshRouter("local")
        router.add_route("dest-a", "hop-1", 2)
        router.add_route("dest-b", "hop-2", 3)
        route = router.find_route("dest-a")
        assert route is not None
        assert route.next_hop == "hop-1"

    def test_better_route_replaces_worse(self):
        router = MeshRouter("local")
        router.add_route("dest", "hop-1", 3)
        router.add_route("dest", "hop-2", 1)
        route = router.find_route("dest")
        assert route.hop_count == 1

    def test_node_status(self):
        node = MeshNode("status-node")
        node.initialize()
        status = node.get_status()
        assert status.node_id == "status-node"
        assert status.uptime_seconds >= 0
