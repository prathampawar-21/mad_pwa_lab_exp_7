"""Async TCP transport with length-prefixed framing."""

import asyncio
import json
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class TransportStats:
    """TCP transport statistics."""
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    connections_active: int = 0
    started_at: float = field(default_factory=time.time)


class TCPTransport:
    """Async TCP transport using asyncio with length-prefixed framing."""

    HEADER_SIZE = 4  # 4-byte length prefix (big-endian uint32)

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 9000,
        message_handler: Optional[Callable] = None,
    ) -> None:
        self._host = host
        self._port = port
        self._message_handler = message_handler
        self._server: Optional[asyncio.Server] = None
        self._connections: dict[str, tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.stats = TransportStats()
        self._running = False

    async def start(self) -> None:
        """Start the TCP server."""
        self._server = await asyncio.start_server(
            self._handle_client, self._host, self._port
        )
        self._running = True

    async def stop(self) -> None:
        """Stop the TCP server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()

        for reader, writer in self._connections.values():
            writer.close()
        self._connections.clear()

    async def connect_to(self, node_id: str, host: str, port: int) -> bool:
        """Connect to a remote node."""
        try:
            reader, writer = await asyncio.open_connection(host, port)
            self._connections[node_id] = (reader, writer)
            self.stats.connections_active += 1
            asyncio.create_task(self._read_messages(node_id, reader))
            return True
        except (OSError, ConnectionRefusedError):
            return False

    async def send(self, node_id: str, message: dict[str, Any]) -> bool:
        """Send a message to a connected node."""
        conn = self._connections.get(node_id)
        if conn is None:
            return False

        _, writer = conn
        try:
            data = json.dumps(message).encode()
            header = struct.pack(">I", len(data))
            writer.write(header + data)
            await writer.drain()
            self.stats.messages_sent += 1
            self.stats.bytes_sent += len(data)
            return True
        except Exception:
            self._connections.pop(node_id, None)
            return False

    async def broadcast(self, message: dict[str, Any]) -> int:
        """Broadcast a message to all connected nodes."""
        sent = 0
        for node_id in list(self._connections.keys()):
            if await self.send(node_id, message):
                sent += 1
        return sent

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming client connection."""
        addr = writer.get_extra_info("peername")
        node_id = f"{addr[0]}:{addr[1]}" if addr else "unknown"
        self._connections[node_id] = (reader, writer)
        self.stats.connections_active += 1
        await self._read_messages(node_id, reader)

    async def _read_messages(
        self, node_id: str, reader: asyncio.StreamReader
    ) -> None:
        """Read length-prefixed messages from a connection."""
        try:
            while self._running:
                header = await reader.readexactly(self.HEADER_SIZE)
                length = struct.unpack(">I", header)[0]
                if length > 10 * 1024 * 1024:  # 10MB max
                    break
                data = await reader.readexactly(length)
                self.stats.messages_received += 1
                self.stats.bytes_received += length

                if self._message_handler:
                    try:
                        message = json.loads(data.decode())
                        await self._message_handler(node_id, message)
                    except json.JSONDecodeError:
                        pass
        except (asyncio.IncompleteReadError, ConnectionResetError, OSError):
            pass
        finally:
            self._connections.pop(node_id, None)
            self.stats.connections_active = max(0, self.stats.connections_active - 1)
