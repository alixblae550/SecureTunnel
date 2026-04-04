"""
Entry node — first hop in the 3-node circuit.

Circuit:  Relay  ──K1──►  Entry  ──K2──►  Middle  ──K3──►  Exit  ──►  Internet

Responsibilities
─────────────────
  • Accept TLS-in-TLS connections from the relay (with anti-probing).
  • Maintain a pool of pre-warmed TLS-in-TLS connections to the middle node.
  • For each relay session: acquire a middle connection, peel the relay's
    encryption layer (K1), re-encrypt with the middle's session key (K2),
    and forward bidirectionally.

Security properties
────────────────────
  • The relay only knows K1 and the entry's address.
  • The entry only knows K1 (with relay) and K2 (with middle).
    It cannot see the plaintext CONNECT target or payload.
  • Compromise of entry alone reveals nothing about destinations.
"""
import asyncio
import secrets

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import NODES
from secure_tunnel.transport.tls_in_tls_transport import (
    tls_in_tls_serve, tls_in_tls_connect,
)
from secure_tunnel.crypto import derive_session_key, mlkem_encapsulate
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.keyring import load_or_generate
from secure_tunnel.logging.anon_logger import log_event
from secure_tunnel.protocol import MSG_DATA, pack_plain, unpack_plain

_entry_cfg  = NODES["entry"]
_middle_cfg = NODES["middle"]

HOST      = _entry_cfg["host"]
PORT      = _entry_cfg["port"]
NODE_NAME = "entry"
CERT      = "cert.pem"
KEY       = "key.pem"

_entry_priv, _entry_pub = load_or_generate(NODE_NAME)

# ---------------------------------------------------------------------------
# Middle-node connection pool
# ---------------------------------------------------------------------------

_POOL_SIZE = 12
_middle_pool: asyncio.Queue | None = None
_middle_fresh_sem: asyncio.Semaphore | None = None


async def _connect_to_middle() -> tuple:
    """Open one TLS-in-TLS connection + hybrid ECDH (K2) with the middle node."""
    ctx = tls_in_tls_connect(_middle_cfg["host"], _middle_cfg["port"], cert=CERT)
    ws  = await ctx.__aenter__()

    from secure_tunnel.crypto import mlkem_generate, mlkem_decapsulate
    x25519_priv = X25519PrivateKey.generate()
    mlkem_priv, mlkem_pub_bytes = mlkem_generate()

    hello: dict = {"pub": x25519_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_pub_bytes is not None:
        hello["mlkem_pub"] = mlkem_pub_bytes
    await ws.send(msgpack.packb(hello, use_bin_type=True))

    raw  = await ws.recv()
    resp = msgpack.unpackb(raw, raw=False)
    peer_pub  = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x25519_ss = x25519_priv.exchange(peer_pub)
    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))
    session_key = derive_session_key(x25519_ss, mlkem_ss)
    return ws, session_key, ctx


async def _pool_filler():
    global _middle_pool
    _middle_pool = asyncio.Queue(maxsize=_POOL_SIZE + 8)
    _last_reported = -1
    while True:
        try:
            needed = _POOL_SIZE - _middle_pool.qsize()
            if needed > 0:
                batch   = min(needed, 4)
                tasks   = [asyncio.wait_for(_connect_to_middle(), timeout=20.0)
                           for _ in range(batch)]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for conn in results:
                    if isinstance(conn, Exception):
                        if not isinstance(conn, (ConnectionError, OSError,
                                                 asyncio.TimeoutError)):
                            print(f"[entry] pool fill error: {type(conn).__name__}: {conn}")
                    else:
                        await _middle_pool.put(conn)
                current = _middle_pool.qsize()
                if current != _last_reported:
                    print(f"[entry] middle pool: {current}/{_POOL_SIZE} ready")
                    _last_reported = current
            else:
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            break
        except (ConnectionError, OSError):
            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"[entry] pool fill error: {type(e).__name__}: {e}")
            await asyncio.sleep(1.0)


async def _acquire_middle():
    if _middle_pool is not None:
        try:
            return _middle_pool.get_nowait()
        except asyncio.QueueEmpty:
            pass
    print("[entry] middle pool empty, creating fresh connection")
    if _middle_fresh_sem is not None:
        async with _middle_fresh_sem:
            return await _connect_to_middle()
    return await _connect_to_middle()


def _return_middle(conn):
    if _middle_pool is not None and not _middle_pool.full():
        try:
            _middle_pool.put_nowait(conn)
            return True
        except asyncio.QueueFull:
            pass
    return False


# ---------------------------------------------------------------------------
# Handler — called for each authenticated relay connection
# ---------------------------------------------------------------------------

async def handler(ws):
    """
    Handle one relay connection.
    ws = TlsInTlsChannel from the relay (already auth-checked by transport layer).
    """
    hop_id = NODE_NAME

    # ── Hybrid ECDH handshake with relay (K1) ────────────────────────────────
    raw   = await ws.recv()
    hello = msgpack.unpackb(raw, raw=False)
    peer_pub  = X25519PublicKey.from_public_bytes(bytes(hello["pub"]))
    x25519_ss = _entry_priv.exchange(peer_pub)

    # ML-KEM: if relay sent a public key, encapsulate and send ciphertext back
    mlkem_ct:  bytes | None = None
    mlkem_ss_: bytes | None = None
    if hello.get("mlkem_pub"):
        mlkem_ct, mlkem_ss_ = mlkem_encapsulate(bytes(hello["mlkem_pub"]))

    relay_key  = derive_session_key(x25519_ss, mlkem_ss_)   # K1
    session_id = secrets.randbits(32)

    reply: dict = {"pub": _entry_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_ct is not None:
        reply["mlkem_ct"] = mlkem_ct
    await ws.send(msgpack.packb(reply, use_bin_type=True))

    # ── Acquire middle connection (K2) ────────────────────────────────────────
    middle_ws, middle_key, middle_ctx = await _acquire_middle()

    # ── Forward relay→middle (peel K1, re-wrap K2) ───────────────────────────
    async def forward_responses():
        """middle → relay: peel K2, re-wrap K1."""
        try:
            async for raw_frame in middle_ws:
                try:
                    plain   = parse_frame(middle_key, raw_frame)
                    _, sid, _, payload = unpack_plain(plain)
                    resp    = build_frame(relay_key, pack_plain(MSG_DATA, session_id, 0, payload))
                    await ws.send(resp)
                except Exception as e:
                    print(f"[entry] forward error: {e}")
        finally:
            ws.close()

    fwd_task = asyncio.create_task(forward_responses())

    async for raw_frame in ws:
        try:
            plain     = parse_frame(relay_key, raw_frame)
            _, _, _, payload = unpack_plain(plain)
            log_event(hop_id, session_id, MSG_DATA, len(payload), "in")
            fwd_frame = build_frame(middle_key,
                                    pack_plain(MSG_DATA, secrets.randbits(32), 0, payload))
            await middle_ws.send(fwd_frame)
            log_event(hop_id, session_id, MSG_DATA, len(payload), "out")
        except Exception as e:
            print(f"[entry] relay→middle error: {e}")
            break

    fwd_task.cancel()
    try:
        await fwd_task
    except asyncio.CancelledError:
        pass

    ws.close()
    middle_ws.close()
    try:
        await middle_ctx.__aexit__(None, None, None)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    global _middle_fresh_sem
    _middle_fresh_sem = asyncio.Semaphore(8)
    asyncio.create_task(_pool_filler())

    print("[entry] warming up middle connection pool…")
    while _middle_pool is None or _middle_pool.empty():
        await asyncio.sleep(0.1)

    def _on_ready():
        print(f"[entry] listening on {HOST}:{PORT} (TLS-in-TLS, anti-probing)", flush=True)

    await tls_in_tls_serve(HOST, PORT, handler, cert=CERT, key=KEY, on_ready=_on_ready)


def _exception_handler(loop, context):
    exc = context.get("exception")
    if isinstance(exc, (ConnectionResetError, BrokenPipeError, OSError)):
        return
    if isinstance(exc, RuntimeError) and "GeneratorExit" in str(exc):
        return
    loop.default_exception_handler(context)


async def _run():
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(_exception_handler)
    await main()


if __name__ == "__main__":
    asyncio.run(_run())
