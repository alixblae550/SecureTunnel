"""
Client-side tunnel relay with connection pool, connection reuse, circuit
rotation, jitter, and cover traffic.

Circuit:  Relay ──K1──► Entry ──K2──► Middle ──K3──► Exit ──► Internet

The relay connects only to the Entry node.  Entry/Middle/Exit handle the
remaining hops transparently.

New in this version
────────────────────
  • CircuitManager — rotate K1/K2/K3 every CIRCUIT_TTL_SECONDS or
    CIRCUIT_MAX_REQUESTS requests.
  • Jitter — random JITTER_MIN_MS…JITTER_MAX_MS delay before each DATA
    frame sent toward the tunnel.
  • Cover traffic — when the tunnel is idle for COVER_MIN_INTERVAL…
    COVER_MAX_INTERVAL seconds, a random-payload cover frame is injected
    so the traffic pattern never shows "silence = no activity".
"""
import asyncio
import math
import os
import secrets
import time

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import (
    ROUTE,
    JITTER_MIN_MS, JITTER_MAX_MS,
    COVER_MIN_INTERVAL, COVER_MAX_INTERVAL,
)
from secure_tunnel.transport.tls_in_tls_transport import tls_in_tls_connect
from secure_tunnel.crypto import derive_session_key, mlkem_generate, mlkem_decapsulate
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.protocol import pack_plain, unpack_plain, MSG_DATA, MSG_COVER
from secure_tunnel.circuit import CircuitManager

# Entry node is always the first (and only) direct peer for the relay
ENTRY_HOST = ROUTE[0]["host"]
ENTRY_PORT = ROUTE[0]["port"]

# Jitter in seconds (converted once for asyncio.sleep)
_JITTER_MIN = JITTER_MIN_MS / 1000.0
_JITTER_MAX = JITTER_MAX_MS / 1000.0


def _sinusoidal_cover_interval() -> float:
    """
    Compute a cover-traffic interval that mimics human activity patterns.

    The interval follows a sinusoidal curve over 24 hours:
      • Peak activity at 14:00 (afternoon) → shortest interval (~3 s)
      • Minimum activity at 03:00 (night)  → longest interval (~60 s)

    A ±15% random jitter is applied so the resulting pattern is never
    perfectly periodic (would be its own fingerprint).

    Day/night model:
        activity(h) = 0.5 × (1 − sin(π × (h − 14) / 12))
        interval    = 3 + (1 − activity) × 57   → range [3 s … 60 s]
    """
    local_hour = time.localtime().tm_hour + time.localtime().tm_min / 60.0
    # Sinusoidal activity: 1.0 at 14:00, 0.0 at 02:00
    phase = math.pi * (local_hour - 14.0) / 12.0
    activity = 0.5 * (1.0 - math.sin(phase))          # 0.0 … 1.0
    base_interval = 3.0 + (1.0 - activity) * 57.0     # 3 s … 60 s
    # ±15% random jitter so the pattern is never perfectly regular
    jitter = 1.0 + (secrets.randbelow(300) - 150) / 1000.0   # 0.85 … 1.15
    return max(2.0, base_interval * jitter)

# ---------------------------------------------------------------------------
# Circuit manager (module-level singleton)
# ---------------------------------------------------------------------------

_circuit = CircuitManager()

# ---------------------------------------------------------------------------
# Bandwidth counters (printed every second for the launcher to parse)
# ---------------------------------------------------------------------------

_bytes_in  = 0   # bytes received from internet through tunnel
_bytes_out = 0   # bytes sent to internet through tunnel
_bw_task: asyncio.Task | None = None


async def _bw_reporter():
    """Print bandwidth stats every second for the launcher to display."""
    global _bytes_in, _bytes_out
    while True:
        await asyncio.sleep(1)
        bi, bo = _bytes_in, _bytes_out
        _bytes_in = 0
        _bytes_out = 0
        print(f"[relay] bw: {bi // 1024}↓ {bo // 1024}↑ KB/s", flush=True)


# ---------------------------------------------------------------------------
# Connection pool
# ---------------------------------------------------------------------------

_POOL_SIZE = 20
_pool: asyncio.Queue | None = None
_fresh_sem: asyncio.Semaphore | None = None
_pool_filler_task: asyncio.Task | None = None


async def _make_connection():
    """
    Open one TLS-in-TLS connection to the entry node and complete the
    hybrid ECDH handshake (K1):
      Classical:    X25519  (PFS against current adversaries)
      Post-quantum: ML-KEM-768 (PFS against future quantum computers)
    """
    ctx = tls_in_tls_connect(ENTRY_HOST, ENTRY_PORT, cert="cert.pem")
    ws = await ctx.__aenter__()

    # ── X25519 ──────────────────────────────────────────────────────────────
    x25519_priv = X25519PrivateKey.generate()
    x25519_pub  = x25519_priv.public_key()

    # ── ML-KEM-768 (post-quantum) — optional ────────────────────────────────
    mlkem_priv, mlkem_pub_bytes = mlkem_generate()

    hello: dict = {"pub": x25519_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_pub_bytes is not None:
        hello["mlkem_pub"] = mlkem_pub_bytes

    await ws.send(msgpack.packb(hello, use_bin_type=True))

    raw  = await ws.recv()
    resp = msgpack.unpackb(raw, raw=False)

    # ── X25519 DH ───────────────────────────────────────────────────────────
    peer_pub    = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x25519_ss   = x25519_priv.exchange(peer_pub)

    # ── ML-KEM decapsulation ─────────────────────────────────────────────────
    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))

    session_key = derive_session_key(x25519_ss, mlkem_ss)
    session_id  = secrets.randbits(32)
    return ws, session_key, session_id, ctx


async def _drain_pool():
    """Close and discard all pooled connections (used during circuit rotation)."""
    global _pool
    if _pool is None:
        return
    while not _pool.empty():
        try:
            conn = _pool.get_nowait()
            ws, _, _, ctx = conn
            try:
                ws.close()
            except Exception:
                pass
            try:
                await ctx.__aexit__(None, None, None)
            except Exception:
                pass
        except asyncio.QueueEmpty:
            break
    print("[relay] pool drained for circuit rotation")


async def _fill_pool_once():
    """Fill pool to _POOL_SIZE (blocking until at least one connection is ready)."""
    if _pool is None:
        return
    needed = _POOL_SIZE - _pool.qsize()
    if needed <= 0:
        return
    batch = min(needed, 4)
    tasks = [asyncio.wait_for(_make_connection(), timeout=20.0)
             for _ in range(batch)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for conn in results:
        if isinstance(conn, Exception):
            if not isinstance(conn, (ConnectionResetError, BrokenPipeError,
                                     ConnectionError, OSError,
                                     asyncio.TimeoutError)):
                print(f"[relay] pool fill error: {type(conn).__name__}: {conn}")
        else:
            await _pool.put(conn)


async def _pool_filler():
    """Background task: keep the pool at _POOL_SIZE ready connections."""
    global _pool
    _pool = asyncio.Queue(maxsize=_POOL_SIZE + 8)
    _last_reported = -1
    while True:
        try:
            needed = _POOL_SIZE - _pool.qsize()
            if needed > 0:
                await _fill_pool_once()
                current = _pool.qsize()
                if current != _last_reported:
                    _last_reported = current
            else:
                await asyncio.sleep(0.05)

            # Periodic circuit rotation check (every fill cycle)
            if _circuit.should_rotate():
                await _circuit.rotate(_drain_pool, _fill_pool_once)

        except asyncio.CancelledError:
            break
        except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"[relay] pool fill error: {type(e).__name__}: {e}")
            await asyncio.sleep(1.0)


async def start_pool():
    """Start background pool filler and wait until first connection is ready."""
    global _fresh_sem, _pool_filler_task
    global _bw_task
    _fresh_sem = asyncio.Semaphore(4)
    _pool_filler_task = asyncio.create_task(_pool_filler())
    _bw_task = asyncio.create_task(_bw_reporter())
    print("[relay] warming up tunnel connection pool...")
    while _pool is None or _pool.empty():
        await asyncio.sleep(0.1)
    print("[relay] tunnel pool ready", flush=True)


async def _acquire_connection():
    """Get a connection from pool or create a fresh one as fallback."""
    if _pool is not None:
        try:
            return _pool.get_nowait()
        except asyncio.QueueEmpty:
            pass
    print("[relay] pool empty, creating fresh connection")
    if _fresh_sem is not None:
        async with _fresh_sem:
            return await _make_connection()
    return await _make_connection()


def _return_to_pool(conn):
    """Return a cleanly-ended connection to the pool for reuse."""
    if _pool is not None and not _pool.full():
        try:
            _pool.put_nowait(conn)
            return True
        except asyncio.QueueFull:
            pass
    return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cmd_helpers(session_key, session_id):
    def _send_cmd(obj: dict) -> bytes:
        payload = msgpack.packb(obj, use_bin_type=True)
        return build_frame(session_key, pack_plain(MSG_DATA, session_id, 0, payload))

    def _parse_cmd(raw_frame: bytes) -> tuple[int, dict]:
        """Returns (msg_type, cmd_dict). For MSG_COVER frames, cmd_dict is {"cmd":"COVER"}."""
        plain = parse_frame(session_key, raw_frame)
        msg_type, _, _, payload = unpack_plain(plain)
        if msg_type == MSG_COVER:
            return MSG_COVER, {"cmd": "COVER"}
        return msg_type, msgpack.unpackb(payload, raw=False)

    def _cover_frame() -> bytes:
        """Build a cover-traffic frame (MSG_COVER type, msgpack payload).
        Receiver identifies cover frames by the message type field (MSG_COVER)
        in unpack_plain(), before attempting command parsing.
        """
        # Pad with random extra bytes so cover frames vary in apparent size
        filler = os.urandom(secrets.randbelow(512) + 64)
        payload = msgpack.packb({"cmd": "COVER", "pad": filler}, use_bin_type=True)
        return build_frame(session_key, pack_plain(MSG_COVER, session_id, 0, payload))

    return _send_cmd, _parse_cmd, _cover_frame


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------

async def relay_through_tunnel(
    browser_reader: asyncio.StreamReader,
    browser_writer: asyncio.StreamWriter,
    host: str,
    port: int,
):
    _circuit.on_request()

    conn = await _acquire_connection()
    ws, session_key, session_id, ctx = conn
    _send_cmd, _parse_cmd, _cover_frame = _make_cmd_helpers(session_key, session_id)

    can_reuse = False
    connect_ok = False
    _deferred_exc: BaseException | None = None

    try:
        print(f"[relay] CONNECT {host}:{port}")

        await ws.send(_send_cmd({"cmd": "CONNECT", "host": host, "port": port}))

        try:
            raw_resp = await asyncio.wait_for(ws.recv(), timeout=15.0)
        except asyncio.TimeoutError:
            raise ConnectionError(f"CONNECT timeout for {host}:{port}")
        except RuntimeError as e:
            # Python 3.14: asyncio.timeout().__aexit__ doesn't handle GeneratorExit
            if "GeneratorExit" in str(e):
                raise ConnectionError("connection interrupted (GeneratorExit)")
            raise

        _, resp_obj = _parse_cmd(raw_resp)
        if resp_obj.get("cmd") != "CONNECT_OK":
            raise ConnectionError(
                f"CONNECT failed: {resp_obj.get('msg', 'unknown error')}"
            )

        connect_ok = True

        browser_writer.write(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        await browser_writer.drain()

        print(f"[relay] {host}:{port} connected, relaying")

        stop_event = asyncio.Event()
        exit_sent_close = asyncio.Event()
        # Updated whenever we send or receive real data (for cover traffic)
        _last_activity = asyncio.get_event_loop().time()

        async def browser_to_tunnel():
            nonlocal _last_activity
            try:
                while not stop_event.is_set():
                    data = await browser_reader.read(65536)
                    if not data:
                        break
                    # Jitter: small random delay before forwarding
                    if _JITTER_MAX > 0:
                        await asyncio.sleep(
                            _JITTER_MIN + (_JITTER_MAX - _JITTER_MIN) * secrets.randbelow(1000) / 1000.0
                        )
                    global _bytes_out
                    _last_activity = asyncio.get_event_loop().time()
                    _bytes_out += len(data)
                    await ws.send(_send_cmd({"cmd": "DATA", "data": data}))
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except Exception as e:
                print(f"[relay] browser->tunnel error: {e}")
            finally:
                stop_event.set()
                try:
                    await ws.send(_send_cmd({"cmd": "CLOSE"}))
                except Exception:
                    pass

        async def tunnel_to_browser():
            global _bytes_in
            nonlocal _last_activity
            try:
                async for raw_frame in ws:
                    try:
                        _, obj = _parse_cmd(raw_frame)
                    except Exception as e:
                        print(f"[relay] tunnel->browser parse error: {e}")
                        break
                    cmd = obj.get("cmd")
                    if cmd == "CLOSE":
                        exit_sent_close.set()
                        break
                    # Discard cover frames — MSG_COVER type detected inside _parse_cmd
                    if cmd == "COVER":
                        continue
                    if stop_event.is_set():
                        continue
                    if cmd == "DATA":
                        data = obj.get("data", b"")
                        _last_activity = asyncio.get_event_loop().time()
                        _bytes_in += len(data)
                        browser_writer.write(
                            bytes(data) if not isinstance(data, bytes) else data
                        )
                        await browser_writer.drain()
            except (ConnectionResetError, BrokenPipeError, OSError):
                pass
            except Exception as e:
                print(f"[relay] tunnel->browser error: {e}")
            finally:
                stop_event.set()

        async def cover_traffic():
            """
            Inject cover frames when the tunnel is idle.

            Interval is computed by _sinusoidal_cover_interval() which
            mimics human activity: shorter waits in the afternoon, longer
            at night — so the traffic pattern resembles a real user rather
            than a machine polling at a fixed rate.
            """
            try:
                while not stop_event.is_set():
                    interval = _sinusoidal_cover_interval()
                    await asyncio.sleep(interval)
                    if stop_event.is_set():
                        break
                    idle = asyncio.get_event_loop().time() - _last_activity
                    if idle >= COVER_MIN_INTERVAL:
                        try:
                            await ws.send(_cover_frame())
                        except Exception:
                            break
            except asyncio.CancelledError:
                pass

        cover_task = asyncio.create_task(cover_traffic())
        await asyncio.gather(browser_to_tunnel(), tunnel_to_browser())
        cover_task.cancel()
        try:
            await cover_task
        except asyncio.CancelledError:
            pass

        # Drain until we receive exit's CLOSE (enables connection reuse)
        if exit_sent_close.is_set():
            can_reuse = True
        else:
            try:
                while True:
                    frame = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    try:
                        _, obj = _parse_cmd(frame)
                        if obj.get("cmd") == "CLOSE":
                            can_reuse = True
                            break
                    except Exception:
                        break
            except (asyncio.TimeoutError, ConnectionError, OSError):
                can_reuse = False

    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        can_reuse = False
        if not connect_ok:
            _deferred_exc = e
    except Exception as e:
        can_reuse = False
        if not connect_ok:
            _deferred_exc = e
        else:
            print(f"[relay] error: {type(e).__name__}: {e}")
    finally:
        if connect_ok:
            try:
                browser_writer.close()
                await browser_writer.wait_closed()
            except Exception:
                pass

    # Pool management always runs before any re-raise
    if can_reuse and _return_to_pool(conn):
        pass
    else:
        try:
            await ctx.__aexit__(None, None, None)
        except Exception:
            pass

    if _deferred_exc is not None:
        raise _deferred_exc


# ---------------------------------------------------------------------------
# UDP relay
# ---------------------------------------------------------------------------

async def relay_udp_through_tunnel(host: str, port: int, data: bytes) -> bytes | None:
    """
    Send a single UDP datagram through the tunnel and return the response.

    Uses a pool connection for the exchange.  After the UDP command completes
    (exit node sends UDP_RESP and loops back to wait for the next command)
    the connection is returned to the pool for reuse by TCP CONNECT sessions.

    Returns the raw UDP payload from the destination, or None on error/timeout.
    """
    conn = await _acquire_connection()
    ws, session_key, session_id, ctx = conn
    _send_cmd, _parse_cmd, _ = _make_cmd_helpers(session_key, session_id)

    uid = secrets.randbits(32)
    resp_data: bytes | None = None
    ok = False
    try:
        await ws.send(_send_cmd({
            "cmd": "UDP",
            "host": host,
            "port": port,
            "data": data,
            "id": uid,
        }))
        raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
        _, obj = _parse_cmd(raw)
        if obj.get("cmd") == "UDP_RESP" and obj.get("id") == uid:
            raw_resp = obj.get("data", b"")
            resp_data = bytes(raw_resp) if not isinstance(raw_resp, bytes) else raw_resp
            ok = True
        else:
            print(f"[relay/udp] unexpected response: {obj.get('cmd')}")
    except asyncio.TimeoutError:
        print(f"[relay/udp] timeout for {host}:{port}")
    except Exception as e:
        print(f"[relay/udp] error: {type(e).__name__}: {e}")

    # After a clean UDP exchange the exit node loops back — connection is reusable.
    if ok and _return_to_pool(conn):
        pass
    else:
        try:
            await ctx.__aexit__(None, None, None)
        except Exception:
            pass

    return resp_data
