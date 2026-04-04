"""
TLS-in-TLS transport layer with anti-probing and Chrome-like TLS settings.

What DPI sees
─────────────
  TCP port 443 (or whatever the node binds)
  TLS 1.3 ClientHello with:
    - SNI = COVER_SNI (e.g. "updates.microsoft.com")
    - Cipher suite order close to Chrome 120 / BoringSSL
    - ALPN: h2, http/1.1
    - Supported groups: X25519, P-256, P-384
  Inside the outer TLS: another TLS ClientHello (inner session)
  Inside the inner TLS: msgpack-framed encrypted commands
  → Looks like a two-layer HTTPS API to any inspector.

Anti-probing (server side)
──────────────────────────
  1. Rate-limit by source IP (check_rate).
  2. Inner-TLS handshake must complete within PROBE_TIMEOUT seconds.
     Failure or non-TLS bytes → send decoy HTTP 503 page, close.
  3. After inner TLS: HMAC challenge (anti_probing.server_challenge).
     Failure → silent drop.

Anti-probing (client side)
──────────────────────────
  After inner TLS: respond to server HMAC challenge (anti_probing.client_respond).

Chrome TLS approximation
────────────────────────
  Python's ssl wraps OpenSSL, not BoringSSL, so the JA3 hash will not
  be identical to Chrome's.  We set:
    - TLS 1.2 minimum, TLS 1.3 maximum (Chrome 120 behaviour)
    - Cipher suite string matching Chrome's BoringSSL preference order
    - ALPN: h2, http/1.1
    - OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_COMPRESSION (same as Chrome)
  For a true 1:1 Chrome fingerprint, replace asyncio.open_connection
  with curl_cffi (pip install curl-cffi) and use impersonate="chrome120".

Wire format inside inner TLS
─────────────────────────────
  [4B big-endian message length][message bytes]
"""
import asyncio
import ssl
import struct
from typing import Optional

import secrets as _secrets

from secure_tunnel.config import COVER_SNI, SNI_POOL, FRONT_HOST, PROBE_TIMEOUT
import secure_tunnel.anti_probing as anti_probing


def _pick_sni() -> str:
    """
    Return the active cover SNI for this connection.
    • If COVER_SNI is pinned (set via env), always use it.
    • Otherwise draw uniformly from SNI_POOL on every connection so each
      outgoing TLS ClientHello shows a different domain to passive observers.
    """
    if COVER_SNI:
        return COVER_SNI
    return SNI_POOL[_secrets.randbelow(len(SNI_POOL))]


# ---------------------------------------------------------------------------
# Chrome-like TLS cipher suites (BoringSSL preference order, OpenSSL names)
# ---------------------------------------------------------------------------

# TLS 1.3 suites (handled automatically by OpenSSL, listed for clarity)
# TLS 1.2 suites in Chrome 120 preference order:
_CHROME_CIPHERS = (
    "TLS_AES_128_GCM_SHA256:"
    "TLS_AES_256_GCM_SHA384:"
    "TLS_CHACHA20_POLY1305_SHA256:"
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384:"
    "ECDHE-ECDSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-CHACHA20-POLY1305:"
    "ECDHE-RSA-AES128-SHA:"
    "ECDHE-RSA-AES256-SHA:"
    "AES128-GCM-SHA256:"
    "AES256-GCM-SHA384:"
    "AES128-SHA:"
    "AES256-SHA"
)

_CHROME_ALPN = ["h2", "http/1.1"]

_DRAIN_THRESHOLD = 131_072  # 128 KB


def _make_client_ctx() -> ssl.SSLContext:
    """
    Build an SSLContext that approximates Chrome 120's TLS ClientHello.

    Key differences from create_default_context():
      - No Windows cert-store loading (avoids Python 3.14 GeneratorExit bug)
      - Cipher order matches BoringSSL / Chrome preference
      - ALPN h2 + http/1.1 (Chrome always sends ALPN)
      - Compression disabled
      - TLS 1.2 min / 1.3 max
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Prefer TLS 1.3; keep 1.2 as fallback for compatibility
    # (ECH requires TLS 1.3 only — TODO: enforce once Python ssl supports ECH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_SSLv2 if hasattr(ssl, "OP_NO_SSLv2") else 0
    ctx.options |= ssl.OP_NO_SSLv3 if hasattr(ssl, "OP_NO_SSLv3") else 0
    ctx.options |= ssl.OP_NO_COMPRESSION
    try:
        ctx.set_ciphers(_CHROME_CIPHERS)
    except ssl.SSLError:
        pass  # older OpenSSL may not support all suites — fall back to default
    try:
        ctx.set_alpn_protocols(_CHROME_ALPN)
    except (AttributeError, ssl.SSLError):
        pass
    return ctx


# ---------------------------------------------------------------------------
# Channel
# ---------------------------------------------------------------------------

class TlsInTlsChannel:
    """
    Bidirectional channel over a second TLS session running inside an outer
    TLS stream.  Provides send / recv / async-iteration interface.
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        ssl_obj: ssl.SSLObject,
        incoming: ssl.MemoryBIO,
        outgoing: ssl.MemoryBIO,
    ):
        self._reader   = reader
        self._writer   = writer
        self._ssl      = ssl_obj
        self._incoming = incoming
        self._outgoing = outgoing
        self._queue: asyncio.Queue = asyncio.Queue()
        self._pump_task: Optional[asyncio.Task] = None
        self._frame_buf = b""

    async def _flush_outgoing(self) -> None:
        data = self._outgoing.read()
        if not data:
            return
        self._writer.write(data)
        try:
            if self._writer.transport.get_write_buffer_size() > _DRAIN_THRESHOLD:
                await self._writer.drain()
        except Exception:
            await self._writer.drain()

    def _parse_frames(self, plain: bytes) -> None:
        self._frame_buf += plain
        while len(self._frame_buf) >= 4:
            length = struct.unpack(">I", self._frame_buf[:4])[0]
            if len(self._frame_buf) < 4 + length:
                break
            frame = self._frame_buf[4:4 + length]
            self._frame_buf = self._frame_buf[4 + length:]
            self._queue.put_nowait(frame)

    async def _pump(self) -> None:
        while True:
            try:
                chunk = await self._reader.read(65536)
                if not chunk:
                    self._queue.put_nowait(None)
                    return
                self._incoming.write(chunk)
                while True:
                    try:
                        plain = self._ssl.read(65535)
                        if plain:
                            self._parse_frames(plain)
                    except ssl.SSLWantReadError:
                        break
                await self._flush_outgoing()
            except Exception as e:
                print(f"[tls-in-tls pump] error: {e}")
                self._queue.put_nowait(None)
                return

    async def send(self, data: bytes) -> None:
        header = struct.pack(">I", len(data))
        self._ssl.write(header + data)
        await self._flush_outgoing()

    async def recv(self) -> bytes:
        item = await self._queue.get()
        if item is None:
            raise ConnectionError("TLS-in-TLS stream closed")
        return item

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except ConnectionError:
            raise StopAsyncIteration

    def close(self) -> None:
        if self._pump_task and not self._pump_task.done():
            self._pump_task.cancel()
            # Schedule awaiting the cancellation so the task actually finishes
            # and doesn't produce "Task was destroyed but it is pending!" warnings.
            asyncio.ensure_future(self._await_pump())
        try:
            self._writer.close()
        except Exception:
            pass

    async def _await_pump(self) -> None:
        try:
            await self._pump_task
        except (asyncio.CancelledError, Exception):
            pass


# ---------------------------------------------------------------------------
# Handshake helpers
# ---------------------------------------------------------------------------

async def _handshake_server(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    inner_ctx: ssl.SSLContext,
) -> TlsInTlsChannel:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    ssl_obj  = inner_ctx.wrap_bio(incoming, outgoing, server_side=True)

    while True:
        try:
            ssl_obj.do_handshake()
            break
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            data = outgoing.read()
            if data:
                writer.write(data)
                await writer.drain()
            chunk = await reader.read(65536)
            if not chunk:
                raise ConnectionError("Client disconnected during inner TLS handshake")
            incoming.write(chunk)

    data = outgoing.read()
    if data:
        writer.write(data)
        await writer.drain()

    channel = TlsInTlsChannel(reader, writer, ssl_obj, incoming, outgoing)
    channel._pump_task = asyncio.ensure_future(channel._pump())
    return channel


async def _handshake_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    inner_ctx: ssl.SSLContext,
    inner_server_hostname: str,
) -> TlsInTlsChannel:
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    ssl_obj  = inner_ctx.wrap_bio(
        incoming, outgoing,
        server_side=False,
        server_hostname=inner_server_hostname,
    )

    while True:
        try:
            ssl_obj.do_handshake()
            break
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            data = outgoing.read()
            if data:
                writer.write(data)
                await writer.drain()
            chunk = await reader.read(65536)
            if not chunk:
                raise ConnectionError("Server disconnected during inner TLS handshake")
            incoming.write(chunk)

    data = outgoing.read()
    if data:
        writer.write(data)
        await writer.drain()

    channel = TlsInTlsChannel(reader, writer, ssl_obj, incoming, outgoing)
    channel._pump_task = asyncio.ensure_future(channel._pump())
    return channel


# ---------------------------------------------------------------------------
# Public API — server
# ---------------------------------------------------------------------------

async def tls_in_tls_serve(
    host: str,
    port: int,
    handler,
    cert: str,
    key: str,
    on_ready=None,
) -> None:
    """
    Start a TLS-in-TLS server with anti-probing protection.

    Anti-probing flow for each incoming connection:
      1. Rate-limit by source IP → drop silently if exceeded.
      2. Outer TLS is handled by asyncio.start_server (standard).
      3. Inner-TLS handshake must complete within PROBE_TIMEOUT s.
         On failure: send decoy HTTP 503, close.
      4. HMAC challenge-response inside inner TLS.
         On failure: silent drop.
      5. Call handler(channel).
    """
    # Server contexts — created once at startup (safe from GeneratorExit bug)
    outer_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    outer_ctx.load_cert_chain(cert, key)
    try:
        outer_ctx.set_alpn_protocols(_CHROME_ALPN)
    except (AttributeError, ssl.SSLError):
        pass

    inner_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    inner_ctx.load_cert_chain(cert, key)

    async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        peer_ip = writer.get_extra_info("peername", ("0.0.0.0", 0))[0]

        # ── 1. Rate limiting ────────────────────────────────────────────────
        if not anti_probing.check_rate(peer_ip):
            # Silent drop — don't even send a RST, just close
            writer.close()
            return

        try:
            # ── 2+3. Inner-TLS handshake with timeout ───────────────────────
            try:
                channel = await asyncio.wait_for(
                    _handshake_server(reader, writer, inner_ctx),
                    timeout=PROBE_TIMEOUT,
                )
            except (ssl.SSLError, asyncio.TimeoutError, ConnectionError, OSError):
                # Probe / scanner — forward to real site (anti-probing 2.0)
                # Pass the outer-TLS SNI so the probe sees the real target server.
                outer_sni = writer.get_extra_info("ssl_object")
                sni_name: str | None = None
                if outer_sni is not None:
                    try:
                        sni_name = outer_sni.server_name   # type: ignore[attr-defined]
                    except AttributeError:
                        pass
                await anti_probing.forward_to_real_site(reader, writer, sni=sni_name)
                return

            # ── 4. HMAC challenge ───────────────────────────────────────────
            if not await anti_probing.server_challenge(channel):
                # Auth failed — silent drop
                return

            # ── 5. Legitimate client ────────────────────────────────────────
            await handler(channel)

        except Exception as e:
            # Suppress noisy but expected errors from probes / resets
            if not isinstance(e, (ConnectionResetError, BrokenPipeError, OSError)):
                print(f"[tls-in-tls server] connection error: {e}")
        finally:
            try:
                writer.close()
            except Exception:
                pass

    server = await asyncio.start_server(
        _handle, host, port, ssl=outer_ctx, reuse_address=True
    )
    if on_ready is not None:
        on_ready()
    async with server:
        await server.serve_forever()


# ---------------------------------------------------------------------------
# Public API — client
# ---------------------------------------------------------------------------

class tls_in_tls_connect:
    """
    Async context manager for TLS-in-TLS client connections.

    Outer TLS uses a Chrome-like ClientHello (cipher order, ALPN, TLS 1.3).
    After inner-TLS handshake: responds to server HMAC auth challenge.

    Domain fronting:
        If FRONT_HOST is set in config, the TCP connection goes to FRONT_HOST
        but the TLS SNI is COVER_SNI.  This enables CDN-based domain fronting
        where the CDN routes based on the inner Host header.

    Usage:
        async with tls_in_tls_connect(host, port, cert="cert.pem") as ch:
            await ch.send(b"...")
    """

    def __init__(
        self,
        host: str,
        port: int,
        cert: Optional[str] = None,
        cover_sni: str = "",   # empty = pick from SNI_POOL per-connection
    ):
        self._host      = host
        self._port      = port
        self._cert      = cert
        self._cover_sni = cover_sni
        self._writer: Optional[asyncio.StreamWriter] = None
        self._channel: Optional[TlsInTlsChannel]     = None

    async def __aenter__(self) -> TlsInTlsChannel:
        # ── Outer TLS — Chrome-like ClientHello ─────────────────────────────
        outer_ctx = _make_client_ctx()

        # Pick cover SNI: per-connection random from pool (or pinned value)
        active_sni = self._cover_sni if self._cover_sni else _pick_sni()

        # Domain fronting: connect to FRONT_HOST if configured, else direct
        tcp_host = FRONT_HOST if FRONT_HOST else self._host

        reader, writer = await asyncio.open_connection(
            tcp_host,
            self._port,
            ssl=outer_ctx,
            server_hostname=active_sni,
        )
        self._writer = writer

        # ── Inner TLS ────────────────────────────────────────────────────────
        inner_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        inner_ctx.check_hostname = False
        inner_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        inner_ctx.options |= ssl.OP_NO_COMPRESSION
        if self._cert:
            inner_ctx.load_verify_locations(self._cert)
            inner_ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            inner_ctx.verify_mode = ssl.CERT_NONE

        self._channel = await _handshake_client(
            reader, writer, inner_ctx,
            inner_server_hostname="tunnel",
        )

        # ── Auth challenge-response ──────────────────────────────────────────
        await anti_probing.client_respond(self._channel)

        return self._channel

    async def __aexit__(self, *args) -> None:
        if self._channel:
            self._channel.close()
        elif self._writer:
            self._writer.close()
