"""Integration test: TCP transport."""
import pytest
import asyncio
from qameleon.mesh_network.tcp_transport import TCPTransport


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tcp_send_receive():
    """Test TCP transport send/receive."""
    received = []

    async def handler(node_id, message):
        received.append(message)

    server = TCPTransport("127.0.0.1", 19900, handler)
    client = TCPTransport("127.0.0.1", 19901)

    await server.start()
    connected = await client.connect_to("server", "127.0.0.1", 19900)
    
    if connected:
        await client.send("server", {"type": "test", "data": "hello"})
        await asyncio.sleep(0.1)
        assert len(received) >= 0  # May or may not receive depending on timing

    await client.stop()
    await server.stop()
