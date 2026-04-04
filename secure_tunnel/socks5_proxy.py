"""
SOCKS5 proxy server.
Accepts browser connections on 127.0.0.1:1080 and routes each
connection through the secure onion tunnel to the exit node.
"""
import asyncio
import os
import socket
import struct

from secure_tunnel.tunnel_relay import relay_through_tunnel, relay_udp_through_tunnel, start_pool
from secure_tunnel.logging.anon_logger import log_event

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = int(os.environ.get("SOCKS5_PORT", "1080"))

_REPLY_FAIL    = b'\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00'
_MAX_UDP_TASKS = 64   # cap concurrent UDP relay coroutines per relay socket
_REPLY_REFUSED = b'\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_BADCMD  = b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'
_REPLY_BADATYP = b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00'


async def _read_exact(reader: asyncio.StreamReader, n: int) -> bytes:
    try:
        return await reader.readexactly(n)
    except asyncio.IncompleteReadError:
        raise ConnectionResetError("connection closed during SOCKS5 handshake")


def _parse_udp_header(data: bytes):
    """Parse SOCKS5 UDP request header (RFC 1928 §7).
    Returns (host, port, payload) or raises ValueError.
    """
    if len(data) < 4:
        raise ValueError("UDP header too short")
    if data[2] != 0:
        raise ValueError("fragmentation not supported")
    atyp = data[3]
    offset = 4
    if atyp == 1:            # IPv4
        if len(data) < offset + 4 + 2:
            raise ValueError("truncated IPv4")
        host = socket.inet_ntoa(data[offset:offset + 4])
        offset += 4
    elif atyp == 3:          # domain name
        if len(data) < offset + 1:
            raise ValueError("truncated domain length")
        n = data[offset]; offset += 1
        if len(data) < offset + n + 2:
            raise ValueError("truncated domain")
        host = data[offset:offset + n].decode()
        offset += n
    elif atyp == 4:          # IPv6
        if len(data) < offset + 16 + 2:
            raise ValueError("truncated IPv6")
        host = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
        offset += 16
    else:
        raise ValueError(f"unknown ATYP {atyp}")
    port = struct.unpack("!H", data[offset:offset + 2])[0]
    payload = data[offset + 2:]
    return host, port, payload


def _build_udp_header(host: str, port: int) -> bytes:
    """Build a minimal SOCKS5 UDP response header (IPv4 0.0.0.0 placeholder)."""
    return b'\x00\x00\x00\x01' + b'\x00\x00\x00\x00' + struct.pack("!H", port)


class _UDPRelay(asyncio.DatagramProtocol):
    """
    asyncio DatagramProtocol that receives UDP datagrams from the SOCKS5
    client, strips the SOCKS5 UDP header, relays through the tunnel, and
    sends responses back with a SOCKS5 UDP header prepended.
    """

    def __init__(self):
        self.transport: asyncio.DatagramTransport | None = None
        self._client_addr: tuple | None = None
        self._active_tasks: int = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr: tuple):
        self._client_addr = addr
        if self._active_tasks >= _MAX_UDP_TASKS:
            log_event("socks5", 0, 0, 0, "udp_flood_drop")
            return  # drop silently under UDP flood — no task spawned
        self._active_tasks += 1
        asyncio.ensure_future(self._relay(data, addr))

    async def _relay(self, data: bytes, client_addr: tuple):
        try:
            try:
                host, port, payload = _parse_udp_header(data)
            except ValueError as e:
                log_event("socks5", 0, 0, 0, f"udp_bad_header:{type(e).__name__}")
                return
            log_event("socks5", 0, 0, len(payload), "udp_relay")
            resp = await relay_udp_through_tunnel(host, port, payload)
            if resp is not None and self.transport and not self.transport.is_closing():
                self.transport.sendto(_build_udp_header(host, port) + resp, client_addr)
        finally:
            self._active_tasks -= 1

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass


async def _handle_udp_associate(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    """
    Handle SOCKS5 CMD=3 (UDP ASSOCIATE).

    1. Open a local UDP socket on a random port.
    2. Reply to the client with that port.
    3. Relay UDP datagrams through the tunnel until the TCP control
       connection is closed by the client.
    """
    loop = asyncio.get_event_loop()
    relay = _UDPRelay()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: relay,
        local_addr=("127.0.0.1", 0),
    )
    _, udp_port = transport.get_extra_info("sockname")
    print(f"[socks5/udp] relay socket on 127.0.0.1:{udp_port}")

    # Inform the client where to send UDP datagrams
    writer.write(
        b'\x05\x00\x00\x01' +
        socket.inet_aton("127.0.0.1") +
        struct.pack("!H", udp_port)
    )
    await writer.drain()

    # The TCP connection must stay open for the lifetime of the UDP session.
    # When the client closes it, we tear down the UDP relay.
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(256), timeout=300.0)
            if not chunk:
                break
    except (asyncio.TimeoutError, ConnectionResetError, OSError):
        pass
    finally:
        transport.close()
        try:
            writer.close()
        except Exception:
            pass
    print(f"[socks5/udp] relay closed (port {udp_port})")


async def handle_socks5(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        # Auth negotiation
        header = await _read_exact(reader, 2)
        if header[0] != 5:
            writer.close()
            return
        nmethods = header[1]
        await _read_exact(reader, nmethods)
        writer.write(b'\x05\x00')
        await writer.drain()

        # Request
        req = await _read_exact(reader, 4)
        if req[0] != 5:
            writer.write(_REPLY_FAIL)
            writer.close()
            return
        cmd = req[1]
        if cmd not in (1, 3):      # 1 = CONNECT, 3 = UDP ASSOCIATE
            writer.write(_REPLY_BADCMD)
            writer.close()
            return

        atyp = req[3]
        if atyp == 1:
            raw = await _read_exact(reader, 4)
            host = socket.inet_ntoa(raw)
        elif atyp == 3:
            length = (await _read_exact(reader, 1))[0]
            host = (await _read_exact(reader, length)).decode()
        elif atyp == 4:
            raw = await _read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, raw)
        else:
            writer.write(_REPLY_BADATYP)
            writer.close()
            return

        port_bytes = await _read_exact(reader, 2)
        port = struct.unpack("!H", port_bytes)[0]

        if cmd == 3:  # UDP ASSOCIATE
            await _handle_udp_associate(reader, writer)
            return

        log_event("socks5", 0, 0, port, "connect")
        try:
            await relay_through_tunnel(reader, writer, host, port)
        except Exception as tunnel_err:
            log_event("socks5", 0, 0, 0, f"tunnel_error:{type(tunnel_err).__name__}")
            # relay_through_tunnel only closes writer when connect_ok;
            # here it failed before that — send error reply then close.
            try:
                writer.write(_REPLY_REFUSED)
                await writer.drain()
            except Exception:
                pass
            try:
                writer.close()
            except Exception:
                pass

    except Exception as e:
        log_event("socks5", 0, 0, 0, f"handshake_error:{type(e).__name__}")
        try:
            writer.write(_REPLY_REFUSED)
            await writer.drain()
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_socks5, SOCKS5_HOST, SOCKS5_PORT, reuse_address=True)
    print(f"[socks5] proxy listening on {SOCKS5_HOST}:{SOCKS5_PORT}", flush=True)
    async with server:
        await server.serve_forever()


def _exception_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
        return
    # Python 3.14 bug: asyncio.timeout().__aexit__ doesn't handle GeneratorExit
    if isinstance(exc, RuntimeError) and "GeneratorExit" in str(exc):
        return
    loop.default_exception_handler(context)


async def _run():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_exception_handler)
    await start_pool()
    await main()


if __name__ == "__main__":
    asyncio.run(_run())
