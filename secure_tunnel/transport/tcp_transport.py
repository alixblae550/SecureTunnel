"""
Simple TCP transport with length-prefixed framing.
Used for local node-to-node connections (127.0.0.1).
All security comes from the ChaCha20-Poly1305 + ECDH layer above.

Wire format: [4 bytes big-endian length][payload bytes]
"""
import asyncio
import struct
from typing import Optional


class TcpChannel:
    """Bidirectional TCP channel with length-prefixed frames."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self._reader = reader
        self._writer = writer

    async def send(self, data: bytes) -> None:
        header = struct.pack(">I", len(data))
        self._writer.write(header + data)
        await self._writer.drain()

    async def recv(self) -> bytes:
        header = await self._reader.readexactly(4)
        length = struct.unpack(">I", header)[0]
        return await self._reader.readexactly(length)

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            raise StopAsyncIteration

    def close(self) -> None:
        try:
            self._writer.close()
        except Exception:
            pass


async def tcp_serve(host: str, port: int, handler) -> None:
    """Start a TCP server. handler(channel) is called for each connection."""
    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        channel = TcpChannel(reader, writer)
        try:
            await handler(channel)
        except Exception as e:
            print(f"[tcp] connection error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(_handle, host, port)
    addr = server.sockets[0].getsockname()
    print(f"[tcp] listening on {addr[0]}:{addr[1]}")
    async with server:
        await server.serve_forever()


class tcp_connect:
    """Async context manager for TCP client connections."""

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port
        self._writer: Optional[asyncio.StreamWriter] = None
        self._channel: Optional[TcpChannel] = None

    async def __aenter__(self) -> TcpChannel:
        reader, writer = await asyncio.open_connection(self._host, self._port)
        self._writer = writer
        self._channel = TcpChannel(reader, writer)
        return self._channel

    async def __aexit__(self, *args) -> None:
        if self._channel:
            self._channel.close()
        elif self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
