"""
Anti-probing module.

Protects tunnel server ports from active probing, fingerprinting, and
enumeration.  Three layers of defence:

1. Rate limiting    — per-IP sliding-window counter; excess connections are
                      silently dropped before any data is exchanged.

2. Real-site proxy  — connections that fail the inner-TLS handshake are
                      transparently forwarded to the *real* HTTPS server whose
                      domain matches the outer-TLS SNI the scanner presented.
                      To a censor, the port is just a boring Microsoft/Google
                      update server.  Falls back to HTTP 503 if the forward
                      fails (e.g. DNS, timeout).

3. HMAC challenge   — after the inner-TLS handshake the server sends a 16-byte
                      random nonce.  The client must reply within 5 s with
                      HMAC-SHA256(AUTH_SECRET, nonce).  Wrong or missing reply
                      → silent drop (no decoy; the probe already passed inner
                      TLS so it is a sophisticated adversary — give it nothing).

All three checks happen inside the already-established outer TLS session, so
they are invisible to passive DPI.
"""

import asyncio
import hashlib
import hmac
import secrets
import time
from typing import TYPE_CHECKING

from secure_tunnel.config import AUTH_SECRET, RATE_LIMIT_PER_MIN, PROBE_TIMEOUT

if TYPE_CHECKING:
    from secure_tunnel.transport.tls_in_tls_transport import TlsInTlsChannel


# ---------------------------------------------------------------------------
# Decoy HTTP response — sent through outer TLS when probe is detected
# ---------------------------------------------------------------------------

_DECOY_BODY = (
    b"<!DOCTYPE html><html><head><title>Service</title></head>"
    b"<body><h1>Service Temporarily Unavailable</h1>"
    b"<p>Please try again later.</p></body></html>"
)

DECOY_RESPONSE: bytes = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Length: " + str(len(_DECOY_BODY)).encode() + b"\r\n"
    b"Connection: close\r\n"
    b"Cache-Control: no-store\r\n"
    b"\r\n" + _DECOY_BODY
)


# ---------------------------------------------------------------------------
# Rate limiting — sliding window per source IP
# ---------------------------------------------------------------------------

# ip → list of monotonic timestamps for connections in the last 60 s
_rate_table: dict[str, list[float]] = {}
_WINDOW = 60.0


def check_rate(ip: str) -> bool:
    """
    Return True if *ip* is within the allowed rate.
    Drops the oldest timestamps outside the sliding window on each call.
    Thread-safe under the GIL (asyncio single-thread).

    Loopback addresses (127.x.x.x, ::1) are always allowed — they are the
    internal relay/node connections and can never be external scanners.
    """
    # Exempt all loopback traffic — internal node-to-node connections
    if ip.startswith("127.") or ip == "::1":
        return True

    now = time.monotonic()
    bucket = _rate_table.get(ip)
    if bucket is None:
        _rate_table[ip] = [now]
        return True
    # Evict expired entries
    cutoff = now - _WINDOW
    bucket = [t for t in bucket if t >= cutoff]
    bucket.append(now)
    _rate_table[ip] = bucket
    # Periodically purge IPs we haven't seen in a while to bound memory
    if len(_rate_table) > 10_000:
        _purge_old()
    return len(bucket) <= RATE_LIMIT_PER_MIN


def _purge_old() -> None:
    cutoff = time.monotonic() - _WINDOW
    dead = [ip for ip, ts in _rate_table.items() if ts and ts[-1] < cutoff]
    for ip in dead:
        del _rate_table[ip]


# ---------------------------------------------------------------------------
# Server-side auth challenge (inside inner TLS)
# ---------------------------------------------------------------------------

async def server_challenge(channel: "TlsInTlsChannel") -> bool:
    """
    Send a random nonce and verify the client's HMAC response.

    Protocol (inside inner TLS):
      S→C  16 random bytes (nonce)
      C→S  32 bytes = HMAC-SHA256(AUTH_SECRET, nonce)

    Returns True if the response is correct, False otherwise.
    Silent drop on failure — no error frame is sent.
    """
    nonce = secrets.token_bytes(16)
    try:
        await channel.send(nonce)
        raw = await asyncio.wait_for(channel.recv(), timeout=PROBE_TIMEOUT)
    except (asyncio.TimeoutError, ConnectionError, OSError):
        return False
    if len(raw) < 32:
        return False
    expected = hmac.new(AUTH_SECRET, nonce, hashlib.sha256).digest()
    return hmac.compare_digest(raw[:32], expected)


# ---------------------------------------------------------------------------
# Client-side auth response (inside inner TLS)
# ---------------------------------------------------------------------------

async def client_respond(channel: "TlsInTlsChannel") -> None:
    """
    Receive nonce from server and reply with HMAC-SHA256(AUTH_SECRET, nonce).
    Raises ConnectionError if the server does not send a nonce in time.
    """
    try:
        nonce = await asyncio.wait_for(channel.recv(), timeout=PROBE_TIMEOUT)
    except asyncio.TimeoutError:
        raise ConnectionError("Auth nonce not received from server")
    response = hmac.new(AUTH_SECRET, nonce, hashlib.sha256).digest()
    await channel.send(response)


# ---------------------------------------------------------------------------
# Decoy helpers
# ---------------------------------------------------------------------------

async def forward_to_real_site(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    sni: str | None = None,
) -> None:
    """
    Anti-probing 2.0 — forward the scanner's connection to the REAL HTTPS
    server that matches the SNI the scanner presented.

    Flow:
      1. Open a raw TCP connection to sni:443 (or fallback host).
      2. Pipe all data bidirectionally between the scanner and the real server.
      3. To the scanner / censor the server is just a normal update/CDN host.

    Falls back to send_decoy() if the forward cannot be established.
    """
    from secure_tunnel.config import SNI_POOL

    # Use provided SNI, else pick the first pool entry as a safe default
    target_host = sni if sni else SNI_POOL[0]
    target_port = 443

    try:
        real_reader, real_writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port, ssl=False),
            timeout=5.0,
        )
    except Exception:
        # Can't reach real site — send 503 as last resort
        await send_decoy(writer)
        return

    # Bidirectional pipe: scanner ↔ real server (raw TCP, no SSL unwrapping)
    async def _pipe(src_r: asyncio.StreamReader, dst_w: asyncio.StreamWriter):
        try:
            while True:
                chunk = await asyncio.wait_for(src_r.read(8192), timeout=30.0)
                if not chunk:
                    break
                dst_w.write(chunk)
                await dst_w.drain()
        except Exception:
            pass
        finally:
            try:
                dst_w.close()
            except Exception:
                pass

    try:
        await asyncio.gather(
            _pipe(reader, real_writer),
            _pipe(real_reader, writer),
        )
    except Exception:
        pass


async def send_decoy(writer: asyncio.StreamWriter) -> None:
    """
    Fallback: write a plausible HTTP 503 through the *outer* TLS writer.
    Prefer forward_to_real_site() over this when possible.
    """
    try:
        writer.write(DECOY_RESPONSE)
        await asyncio.wait_for(writer.drain(), timeout=3.0)
    except Exception:
        pass
