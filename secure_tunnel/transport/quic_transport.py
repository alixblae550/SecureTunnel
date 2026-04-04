"""
QUIC/HTTP3 transport layer.

Provides QuicChannel — a WebSocket-compatible interface (send/recv/aiter)
so that exit_node, node1, onion_client require minimal changes.

Wire format inside each QUIC stream:
  [4 bytes big-endian length][payload bytes]

DPI sees: UDP port 443, QUIC handshake, CRYPTO frames — identical to Chrome/HTTP3.
"""
import asyncio
import struct
from typing import Optional

from aioquic.asyncio import connect, serve
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived, HandshakeCompleted


# ---------------------------------------------------------------------------
# Internal channel — bridges event-driven QUIC to async send/recv
# ---------------------------------------------------------------------------

class QuicChannel:
    """WebSocket-compatible interface over a single QUIC bidirectional stream."""

    def __init__(self, protocol: "TunnelProtocol", stream_id: int):
        self._proto = protocol
        self._stream_id = stream_id
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._buf = b""          # reassembly buffer for length-prefixed frames
        self._closed = False

    # --- called by TunnelProtocol when data arrives on our stream ---
    def _feed(self, data: bytes) -> None:
        self._buf += data
        while True:
            if len(self._buf) < 4:
                break
            length = struct.unpack(">I", self._buf[:4])[0]
            if len(self._buf) < 4 + length:
                break
            frame = self._buf[4:4 + length]
            self._buf = self._buf[4 + length:]
            self._queue.put_nowait(frame)

    def _close(self) -> None:
        self._closed = True
        self._queue.put_nowait(None)  # sentinel

    # --- public API (mirrors websockets) ---

    async def send(self, data: bytes) -> None:
        header = struct.pack(">I", len(data))
        self._proto._quic.send_stream_data(self._stream_id, header + data)
        self._proto.transmit()

    async def recv(self) -> bytes:
        item = await self._queue.get()
        if item is None:
            raise ConnectionError("QUIC stream closed")
        return item

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except ConnectionError:
            raise StopAsyncIteration


# ---------------------------------------------------------------------------
# Server-side protocol
# ---------------------------------------------------------------------------

class TunnelServerProtocol(QuicConnectionProtocol):
    """
    One instance per QUIC connection.
    Calls self._handler(channel) for the first bidirectional stream opened
    by the client — same signature as a WebSocket handler.
    """

    handler = None          # set by quic_serve()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channels: dict[int, QuicChannel] = {}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid not in self._channels:
                channel = QuicChannel(self, sid)
                self._channels[sid] = channel
                # Schedule handler coroutine
                asyncio.ensure_future(self.__class__.handler(channel))
            self._channels[sid]._feed(event.data)
            if event.end_stream:
                self._channels[sid]._close()


# ---------------------------------------------------------------------------
# Client-side protocol
# ---------------------------------------------------------------------------

class TunnelClientProtocol(QuicConnectionProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._channels: dict[int, QuicChannel] = {}
        self._handshake_done: asyncio.Event = asyncio.Event()

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self._handshake_done.set()
        elif isinstance(event, StreamDataReceived):
            sid = event.stream_id
            if sid in self._channels:
                self._channels[sid]._feed(event.data)
                if event.end_stream:
                    self._channels[sid]._close()

    def open_channel(self) -> QuicChannel:
        sid = self._quic.get_next_available_stream_id()
        channel = QuicChannel(self, sid)
        self._channels[sid] = channel
        return channel


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def make_server_config(cert_path: str, key_path: str) -> QuicConfiguration:
    cfg = QuicConfiguration(is_client=False, alpn_protocols=["h3"])
    cfg.load_cert_chain(cert_path, key_path)
    return cfg


def make_client_config(cert_path: Optional[str] = None) -> QuicConfiguration:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    if cert_path:
        cfg.load_verify_locations(cert_path)
    else:
        # Disable verification for self-signed certs in dev
        cfg.verify_mode = False  # type: ignore[assignment]
    return cfg


async def quic_serve(host: str, port: int, handler, cert: str, key: str):
    """Start QUIC server. handler(channel) mirrors websockets.serve signature."""

    class _Proto(TunnelServerProtocol):
        pass

    _Proto.handler = staticmethod(handler)
    config = make_server_config(cert, key)
    await serve(host, port, configuration=config, create_protocol=_Proto)
    await asyncio.Future()  # run forever


class quic_connect:
    """
    Async context manager — mirrors `async with websockets.connect(...) as ws`.

    Usage:
        async with quic_connect(host, port, cert=...) as channel:
            await channel.send(b"hello")
    """

    def __init__(self, host: str, port: int, cert: Optional[str] = None):
        self._host = host
        self._port = port
        self._cert = cert
        self._conn = None
        self._channel: Optional[QuicChannel] = None

    async def __aenter__(self) -> QuicChannel:
        config = make_client_config(self._cert)
        self._conn = await connect(
            self._host,
            self._port,
            configuration=config,
            create_protocol=TunnelClientProtocol,
        ).__aenter__()
        await self._conn._handshake_done.wait()
        self._channel = self._conn.open_channel()
        return self._channel

    async def __aexit__(self, *args):
        if self._conn:
            await self._conn.__aexit__(*args)
