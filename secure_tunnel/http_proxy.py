"""
HTTP CONNECT proxy — listens on 127.0.0.1:8080 (configurable via HTTP_PORT env).
Accepts HTTP CONNECT requests and tunnels them through the local SOCKS5 proxy
(127.0.0.1:1080).  This makes the tunnel compatible with every Windows app
that supports an HTTP proxy (Telegram, Edge, Discord, Steam, etc.).
"""
import asyncio
import os
import struct

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = int(os.environ.get("HTTP_PORT", "8080"))
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = int(os.environ.get("SOCKS5_PORT", "1080"))


async def _socks5_connect(host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a connection through the local SOCKS5 proxy."""
    reader, writer = await asyncio.open_connection(SOCKS5_HOST, SOCKS5_PORT)

    # Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    if resp[1] != 0x00:
        writer.close()
        raise ConnectionError("SOCKS5 auth method rejected")

    # CONNECT request
    host_bytes = host.encode()
    request = (
        b"\x05\x01\x00\x03"
        + bytes([len(host_bytes)])
        + host_bytes
        + struct.pack("!H", port)
    )
    writer.write(request)
    await writer.drain()

    # Reply: VER, REP, RSV, ATYP, ...
    header = await reader.readexactly(4)
    if header[1] != 0x00:
        writer.close()
        raise ConnectionError(f"SOCKS5 CONNECT failed, REP={header[1]}")

    # Skip bound address
    atyp = header[3]
    if atyp == 0x01:
        await reader.readexactly(4 + 2)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        await reader.readexactly(length + 2)
    elif atyp == 0x04:
        await reader.readexactly(16 + 2)

    return reader, writer


async def _relay(r1: asyncio.StreamReader, w1: asyncio.StreamWriter,
                 r2: asyncio.StreamReader, w2: asyncio.StreamWriter) -> None:
    stop = asyncio.Event()

    async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while not stop.is_set():
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            stop.set()

    await asyncio.gather(pipe(r1, w2), pipe(r2, w1))

    for w in (w1, w2):
        try:
            w.close()
        except Exception:
            pass


async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
    peer = client_w.get_extra_info("peername", ("?", 0))
    try:
        # Read the CONNECT line, e.g. "CONNECT example.com:443 HTTP/1.1\r\n"
        line = await asyncio.wait_for(client_r.readline(), timeout=10)
        if not line:
            return
        parts = line.decode(errors="replace").strip().split()
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            client_w.write(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            await client_w.drain()
            return

        host_port = parts[1]
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host, port = host_port, 443

        # Drain remaining headers
        while True:
            hdr = await asyncio.wait_for(client_r.readline(), timeout=5)
            if hdr in (b"\r\n", b"\n", b""):
                break

        # Connect through SOCKS5
        # 30s: allows up to 4 batches of fresh TLS connections through the semaphore
        # (each batch ~2s TLS + ~2s exit CONNECT = ~4s, 4 batches = 16s + margin)
        try:
            socks_r, socks_w = await asyncio.wait_for(
                _socks5_connect(host, port), timeout=30
            )
        except Exception as e:
            client_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await client_w.drain()
            print(f"[http_proxy] {peer} -> {host}:{port} FAILED: {e}")
            return

        client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_w.drain()
        print(f"[http_proxy] {peer} -> {host}:{port} OK")

        await _relay(client_r, client_w, socks_r, socks_w)

    except (ConnectionResetError, BrokenPipeError, asyncio.TimeoutError, OSError):
        pass
    except Exception as e:
        print(f"[http_proxy] error from {peer}: {e}")
    finally:
        try:
            client_w.close()
        except Exception:
            pass


def _exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
        return
    # Python 3.14 bug: asyncio.timeout().__aexit__ doesn't handle GeneratorExit
    if isinstance(exc, RuntimeError) and "GeneratorExit" in str(exc):
        return
    loop.default_exception_handler(context)


async def main() -> None:
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_exception_handler)
    server = await asyncio.start_server(handle, LISTEN_HOST, LISTEN_PORT, reuse_address=True)
    print(f"[http_proxy] listening on {LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
