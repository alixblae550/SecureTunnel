"""
Middle node — second hop in the 3-node circuit.

Circuit:  Relay  ──K1──►  Entry  ──K2──►  Middle  ──K3──►  Exit  ──►  Internet

Responsibilities
─────────────────
  • Accept TLS-in-TLS connections from the entry node (with anti-probing).
  • Maintain a pool of pre-warmed TLS-in-TLS connections to the exit node.
  • For each entry session: acquire an exit connection, peel K2, re-encrypt
    with K3, and forward bidirectionally.
  • Support circuit EXTEND: handle RELAY_HANDSHAKE (K2 independent key
    negotiation) and EXTEND_K3 (forward K3 negotiation to exit).

Security properties
────────────────────
  • Middle knows K2 (with entry) and K3 (with exit).
  • It cannot see the relay's K1, nor the plaintext CONNECT target.
  • Compromise of middle alone reveals nothing useful to an adversary.
"""
import asyncio
import secrets

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import NODES, POOL_SIZE, POOL_SEMAPHORE
from secure_tunnel.transport.tls_in_tls_transport import (
    tls_in_tls_serve, tls_in_tls_connect,
)
from secure_tunnel.crypto import derive_session_key, mlkem_generate, mlkem_encapsulate, mlkem_decapsulate
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.keyring import load_or_generate
from secure_tunnel.logging.anon_logger import log_event
from secure_tunnel.protocol import MSG_DATA, pack_plain, unpack_plain

_middle_cfg = NODES["middle"]
_exit_cfg   = NODES["exit"]

HOST      = _middle_cfg["host"]
PORT      = _middle_cfg["port"]
NODE_NAME = "node1"      # keyring / log name kept for backward compat
CERT      = "cert.pem"
KEY       = "key.pem"

_node1_priv, _node1_pub = load_or_generate(NODE_NAME)

# ---------------------------------------------------------------------------
# Exit-node connection pool
# ---------------------------------------------------------------------------

_POOL_SIZE = POOL_SIZE
_exit_pool: asyncio.Queue | None = None
_exit_fresh_sem: asyncio.Semaphore | None = None


async def connect_to_exit(priv, pub):
    """Hybrid ECDH (K3) with the exit node."""
    ctx = tls_in_tls_connect(_exit_cfg["host"], _exit_cfg["port"], cert=CERT)
    ws  = await ctx.__aenter__()

    mlkem_priv, mlkem_pub_bytes = mlkem_generate()
    hello: dict = {"pub": pub.public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_pub_bytes is not None:
        hello["mlkem_pub"] = mlkem_pub_bytes
    await ws.send(msgpack.packb(hello, use_bin_type=True))

    raw  = await ws.recv()
    resp = msgpack.unpackb(raw, raw=False)
    exit_pub  = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x25519_ss = priv.exchange(exit_pub)
    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))
    session_key = derive_session_key(x25519_ss, mlkem_ss)
    return ws, session_key, ctx


async def _pool_filler():
    global _exit_pool
    _exit_pool = asyncio.Queue(maxsize=_POOL_SIZE + 8)
    _last_reported = -1
    while True:
        try:
            needed = _POOL_SIZE - _exit_pool.qsize()
            if needed > 0:
                batch   = min(needed, 4)
                tasks   = [asyncio.wait_for(
                               connect_to_exit(_node1_priv, _node1_pub), timeout=15.0)
                           for _ in range(batch)]
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for conn in results:
                    if isinstance(conn, Exception):
                        if not isinstance(conn, (ConnectionResetError, BrokenPipeError,
                                                 ConnectionError, OSError,
                                                 asyncio.TimeoutError)):
                            log_event(NODE_NAME, 0, 0, 0,
                                      f"pool_fill_error:{type(conn).__name__}")
                    else:
                        await _exit_pool.put(conn)
                current = _exit_pool.qsize()
                if current != _last_reported:
                    log_event(NODE_NAME, 0, 0, current, "pool_ready")
                    _last_reported = current
            else:
                await asyncio.sleep(0.05)
        except asyncio.CancelledError:
            break
        except (ConnectionResetError, BrokenPipeError, ConnectionError, OSError):
            await asyncio.sleep(0.5)
        except Exception as e:
            log_event(NODE_NAME, 0, 0, 0, f"pool_fill_error:{type(e).__name__}")
            await asyncio.sleep(1.0)


async def _acquire_exit():
    if _exit_pool is not None:
        try:
            return _exit_pool.get_nowait()
        except asyncio.QueueEmpty:
            pass
    log_event(NODE_NAME, 0, 0, 0, "pool_empty_fresh_conn")
    if _exit_fresh_sem is not None:
        async with _exit_fresh_sem:
            return await connect_to_exit(_node1_priv, _node1_pub)
    return await connect_to_exit(_node1_priv, _node1_pub)


# ---------------------------------------------------------------------------
# EXTEND helpers
# ---------------------------------------------------------------------------

def _wrap_entry(entry_key: bytes, sid: int, obj: dict) -> bytes:
    payload = msgpack.packb(obj, use_bin_type=True)
    return build_frame(entry_key, pack_plain(MSG_DATA, sid, 0, payload))


def _wrap_exit(exit_key: bytes, obj: dict) -> bytes:
    payload = msgpack.packb(obj, use_bin_type=True)
    return build_frame(exit_key, pack_plain(MSG_DATA, secrets.randbits(32), 0, payload))


async def _handle_relay_handshake(
    ws, entry_key: bytes, session_id: int, req: dict
) -> None:
    """
    Handle RELAY_HANDSHAKE from entry on behalf of the relay client.
    Middle generates a fresh ephemeral key pair, performs ECDH with
    the client's public key, and responds — allowing the client to
    independently derive K2.
    """
    client_x_pub_bytes = bytes(req["pub"])
    client_x_pub = X25519PublicKey.from_public_bytes(client_x_pub_bytes)

    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ML-KEM encapsulation against client's PQ key (if provided)
    mlkem_ct: bytes | None = None
    if req.get("mlkem_pub"):
        mlkem_ct, _ = mlkem_encapsulate(bytes(req["mlkem_pub"]))

    reply: dict = {"pub": eph_pub_bytes}
    if mlkem_ct is not None:
        reply["mlkem_ct"] = mlkem_ct
    await ws.send(_wrap_entry(entry_key, session_id, reply))
    log_event(NODE_NAME, session_id, 0, 0, "relay_handshake_ok")


async def _handle_extend_k3(
    ws, entry_key: bytes, session_id: int,
    exit_ws, exit_key: bytes,
    req: dict,
) -> None:
    """
    Handle EXTEND_K3 from entry: forward a RELAY_HANDSHAKE to exit so the
    relay client can independently derive K3.

    Flow:
      entry  →[K2]→  middle  →[K3]→  exit
                                        ↓  generates ephemeral keys
      entry  ←[K2]←  middle  ←[K3]←  exit
    """
    extend_msg = {"cmd": "RELAY_HANDSHAKE", "pub": req["pub"]}
    if req.get("mlkem_pub"):
        extend_msg["mlkem_pub"] = req["mlkem_pub"]

    await exit_ws.send(_wrap_exit(exit_key, extend_msg))
    raw_resp = await asyncio.wait_for(exit_ws.recv(), timeout=10.0)
    plain_resp = parse_frame(exit_key, raw_resp)
    _, _, _, resp_payload = unpack_plain(plain_resp)
    resp_obj = msgpack.unpackb(resp_payload, raw=False)

    reply: dict = {"pub": resp_obj["pub"]}
    if resp_obj.get("mlkem_ct"):
        reply["mlkem_ct"] = resp_obj["mlkem_ct"]
    await ws.send(_wrap_entry(entry_key, session_id, reply))
    log_event(NODE_NAME, session_id, 0, 0, "extend_k3_ok")


# ---------------------------------------------------------------------------
# Handler — called for each authenticated entry connection
# ---------------------------------------------------------------------------

async def handler(ws):
    hop_id = NODE_NAME

    # ── Hybrid ECDH handshake with entry (K2) ────────────────────────────────
    raw   = await ws.recv()
    hello = msgpack.unpackb(raw, raw=False)
    peer_pub  = X25519PublicKey.from_public_bytes(bytes(hello["pub"]))
    x25519_ss = _node1_priv.exchange(peer_pub)

    mlkem_ct_:  bytes | None = None
    mlkem_ss_:  bytes | None = None
    if hello.get("mlkem_pub"):
        mlkem_ct_, mlkem_ss_ = mlkem_encapsulate(bytes(hello["mlkem_pub"]))

    entry_key  = derive_session_key(x25519_ss, mlkem_ss_)   # K2
    session_id = secrets.randbits(32)

    reply: dict = {"pub": _node1_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_ct_ is not None:
        reply["mlkem_ct"] = mlkem_ct_
    await ws.send(msgpack.packb(reply, use_bin_type=True))

    # ── Acquire exit connection (K3) ──────────────────────────────────────────
    exit_ws, exit_key, exit_ctx = await _acquire_exit()

    # ── EXTEND phase (before forwarding loop) ────────────────────────────────
    # Handle RELAY_HANDSHAKE (for K2) and EXTEND_K3 (for K3) before the
    # main bidirectional forward loop starts.
    first_payload: bytes | None = None

    while True:
        raw_frame = await ws.recv()
        try:
            plain = parse_frame(entry_key, raw_frame)
        except Exception as e:
            log_event(hop_id, session_id, 0, 0, f"parse_error:{e}")
            break
        _, _, _, payload = unpack_plain(plain)
        obj = msgpack.unpackb(payload, raw=False)
        cmd = obj.get("cmd")

        if cmd == "RELAY_HANDSHAKE":
            try:
                await _handle_relay_handshake(ws, entry_key, session_id, obj)
            except Exception as e:
                log_event(hop_id, session_id, 0, 0, f"relay_handshake_error:{e}")
                ws.close()
                exit_ws.close()
                return
            continue

        if cmd == "EXTEND_K3":
            try:
                await _handle_extend_k3(ws, entry_key, session_id, exit_ws, exit_key, obj)
            except Exception as e:
                log_event(hop_id, session_id, 0, 0, f"extend_k3_error:{e}")
                ws.close()
                exit_ws.close()
                return
            continue

        # First non-EXTEND frame — enter the forward loop
        first_payload = payload
        break

    if first_payload is None:
        ws.close()
        exit_ws.close()
        try:
            await exit_ctx.__aexit__(None, None, None)
        except Exception:
            pass
        return

    # ── Forward entry→exit (peel K2, re-wrap K3) ─────────────────────────────
    async def forward_responses():
        """exit → entry: peel K3, re-wrap K2."""
        try:
            async for raw_frame in exit_ws:
                try:
                    plain = parse_frame(exit_key, raw_frame)
                    _, sid, _, payload = unpack_plain(plain)
                    resp  = build_frame(entry_key,
                                        pack_plain(MSG_DATA, session_id, 0, payload))
                    await ws.send(resp)
                except Exception as e:
                    log_event(hop_id, session_id, 0, 0, f"fwd_error:{e}")
        finally:
            ws.close()

    fwd_task = asyncio.create_task(forward_responses())

    # Handle the first payload already read in the EXTEND phase
    try:
        fwd_frame = build_frame(exit_key,
                                pack_plain(MSG_DATA, secrets.randbits(32), 0, first_payload))
        await exit_ws.send(fwd_frame)
        log_event(hop_id, session_id, MSG_DATA, len(first_payload), "in")
    except Exception as e:
        log_event(hop_id, session_id, 0, 0, f"first_fwd_error:{e}")
        fwd_task.cancel()
        ws.close()
        exit_ws.close()
        return

    async for raw_frame in ws:
        try:
            plain = parse_frame(entry_key, raw_frame)
            _, _, _, payload = unpack_plain(plain)
            log_event(hop_id, session_id, MSG_DATA, len(payload), "in")
            fwd_frame = build_frame(exit_key,
                                    pack_plain(MSG_DATA, secrets.randbits(32), 0, payload))
            await exit_ws.send(fwd_frame)
            log_event(hop_id, session_id, MSG_DATA, len(payload), "out")
        except Exception as e:
            log_event(hop_id, session_id, 0, 0, f"entry_exit_error:{e}")
            break

    fwd_task.cancel()
    try:
        await fwd_task
    except asyncio.CancelledError:
        pass

    ws.close()
    exit_ws.close()
    try:
        await exit_ctx.__aexit__(None, None, None)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main():
    global _exit_fresh_sem
    _exit_fresh_sem = asyncio.Semaphore(POOL_SEMAPHORE)
    asyncio.create_task(_pool_filler())

    print("[node1] warming up exit connection pool…")
    while _exit_pool is None or _exit_pool.empty():
        await asyncio.sleep(0.1)

    def _on_ready():
        print(f"[node1] listening on {HOST}:{PORT} (TLS-in-TLS)", flush=True)

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
