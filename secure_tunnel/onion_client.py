"""
Onion client — builds a true 3-hop onion circuit.

Circuit:  Client  ──K1──►  Entry  ──K2──►  Middle  ──K3──►  Exit  ──►  Internet

Key negotiation (Tor-style EXTEND):
  1. Connect to entry, negotiate K1 (standard hybrid ECDH handshake).
  2. Send EXTEND_K2 through K1 — entry relays handshake to middle, client
     derives K2 independently (entry never learns K2).
  3. Send EXTEND_K3 through K1 — entry relays to middle through K2, middle
     relays to exit, client derives K3 independently.

Data transmission uses onion.build_onion_packet(data, [K1, K2, K3]):
  • Each hop peels its own encryption layer and forwards the inner bytes.
  • Exit reads the plaintext CONNECT command and connects to the target.

Usage:
    python -m secure_tunnel.onion_client
"""
import asyncio
import secrets

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import ROUTE
from secure_tunnel.transport.tls_in_tls_transport import tls_in_tls_connect
from secure_tunnel.crypto import derive_session_key, mlkem_generate, mlkem_decapsulate, HAS_MLKEM
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.onion import build_onion_packet, peel_onion_layer
from secure_tunnel.protocol import pack_plain, unpack_plain, MSG_DATA

ENTRY_HOST = ROUTE[0]["host"]
ENTRY_PORT = ROUTE[0]["port"]
CERT = "cert.pem"


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _pack(session_key: bytes, sid: int, obj: dict) -> bytes:
    payload = msgpack.packb(obj, use_bin_type=True)
    return build_frame(session_key, pack_plain(MSG_DATA, sid, 0, payload))


def _unpack(session_key: bytes, raw_frame: bytes) -> dict:
    plain = parse_frame(session_key, raw_frame)
    _, _, _, payload = unpack_plain(plain)
    return msgpack.unpackb(payload, raw=False)


# ---------------------------------------------------------------------------
# Step 1 — K1 handshake with entry
# ---------------------------------------------------------------------------

async def _handshake_k1(ws) -> tuple[bytes, int]:
    """
    Perform hybrid ECDH with the entry node.
    Returns (k1_session_key, session_id).
    """
    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    mlkem_priv, mlkem_pub_bytes = mlkem_generate()

    hello: dict = {"pub": x_pub_bytes}
    if mlkem_pub_bytes:
        hello["mlkem_pub"] = mlkem_pub_bytes
    await ws.send(msgpack.packb(hello, use_bin_type=True))

    raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
    resp = msgpack.unpackb(raw, raw=False)

    peer_pub = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x_ss = x_priv.exchange(peer_pub)

    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))

    k1 = derive_session_key(x_ss, mlkem_ss)
    sid = secrets.randbits(32)
    print(f"[onion_client] K1 established "
          f"({'X25519+ML-KEM' if mlkem_ss else 'X25519'})")
    return k1, sid


# ---------------------------------------------------------------------------
# Step 2 — EXTEND K2 (entry relays handshake to middle)
# ---------------------------------------------------------------------------

async def _extend_k2(ws, k1: bytes, sid: int) -> bytes:
    """
    Ask the entry node to relay a handshake to middle so we get K2
    without entry ever learning K2.
    Returns k2_session_key.
    """
    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    mlkem_priv, mlkem_pub_bytes = mlkem_generate()

    req: dict = {"cmd": "EXTEND_K2", "pub": x_pub_bytes}
    if mlkem_pub_bytes:
        req["mlkem_pub"] = mlkem_pub_bytes
    await ws.send(_pack(k1, sid, req))

    raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
    resp = _unpack(k1, raw)
    if resp.get("cmd") != "EXTEND_K2_OK":
        raise ConnectionError(f"EXTEND_K2 failed: {resp}")

    peer_pub = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x_ss = x_priv.exchange(peer_pub)

    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))

    k2 = derive_session_key(x_ss, mlkem_ss)
    print(f"[onion_client] K2 established "
          f"({'X25519+ML-KEM' if mlkem_ss else 'X25519'})")
    return k2


# ---------------------------------------------------------------------------
# Step 3 — EXTEND K3 (entry→middle relay handshake to exit)
# ---------------------------------------------------------------------------

async def _extend_k3(ws, k1: bytes, sid: int) -> bytes:
    """
    Ask the entry→middle chain to relay a handshake to exit so we get K3.
    Returns k3_session_key.
    """
    x_priv = X25519PrivateKey.generate()
    x_pub_bytes = x_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    mlkem_priv, mlkem_pub_bytes = mlkem_generate()

    req: dict = {"cmd": "EXTEND_K3", "pub": x_pub_bytes}
    if mlkem_pub_bytes:
        req["mlkem_pub"] = mlkem_pub_bytes
    await ws.send(_pack(k1, sid, req))

    raw = await asyncio.wait_for(ws.recv(), timeout=10.0)
    resp = _unpack(k1, raw)
    if resp.get("cmd") != "EXTEND_K3_OK":
        raise ConnectionError(f"EXTEND_K3 failed: {resp}")

    peer_pub = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    x_ss = x_priv.exchange(peer_pub)

    mlkem_ss: bytes | None = None
    if mlkem_priv is not None and resp.get("mlkem_ct"):
        mlkem_ss = mlkem_decapsulate(mlkem_priv, bytes(resp["mlkem_ct"]))

    k3 = derive_session_key(x_ss, mlkem_ss)
    print(f"[onion_client] K3 established "
          f"({'X25519+ML-KEM' if mlkem_ss else 'X25519'})")
    return k3


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def build_circuit() -> tuple:
    """
    Build a complete 3-hop onion circuit.

    Returns (ws, ctx, k1, k2, k3, session_id) where ws is the open
    TLS-in-TLS connection to the entry node.  The caller is responsible
    for closing ctx when done.
    """
    ctx = tls_in_tls_connect(ENTRY_HOST, ENTRY_PORT, cert=CERT)
    ws = await ctx.__aenter__()

    k1, sid = await _handshake_k1(ws)
    k2 = await _extend_k2(ws, k1, sid)
    k3 = await _extend_k3(ws, k1, sid)

    print("[onion_client] 3-hop circuit ready")
    return ws, ctx, k1, k2, k3, sid


async def send_onion(ws, k1: bytes, k2: bytes, k3: bytes, sid: int,
                     app_data: bytes) -> None:
    """Send app_data wrapped in a 3-layer onion packet."""
    packet = build_onion_packet(app_data, [k1, k2, k3])
    await ws.send(packet)


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

async def main():
    print(f"[onion_client] ML-KEM available: {HAS_MLKEM}")
    ws, ctx, k1, k2, k3, sid = await build_circuit()

    try:
        connect_cmd = msgpack.packb(
            {"cmd": "CONNECT", "host": "example.com", "port": 80},
            use_bin_type=True,
        )
        await send_onion(ws, k1, k2, k3, sid, connect_cmd)
        print("[onion_client] CONNECT sent through 3-layer onion")

        raw_resp = await asyncio.wait_for(ws.recv(), timeout=10.0)
        is_final, inner = peel_onion_layer(k1, raw_resp)
        print(f"[onion_client] response (final={is_final}): {inner[:80]}")
    except asyncio.TimeoutError:
        print("[onion_client] timeout waiting for response")
    except Exception as e:
        print(f"[onion_client] error: {e}")
    finally:
        try:
            await ctx.__aexit__(None, None, None)
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
