"""
Onion client.
Connects to node1, performs ECDH, sends onion-wrapped data,
receives and decrypts the response.
"""
import asyncio
import secrets

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import ROUTE
from secure_tunnel.transport.tls_in_tls_transport import tls_in_tls_connect
from secure_tunnel.traffic_shaping.shaper import ShapedChannel
from secure_tunnel.traffic_shaping.profiles import HTTPSBrowsingProfile
from secure_tunnel.crypto import derive_session_key
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.onion import build_onion_packet
from secure_tunnel.protocol import pack_plain, unpack_plain, MSG_DATA
from secure_tunnel.dummy_scheduler import run_dummy_sender

NODE1_HOST = ROUTE[0]["host"]
NODE1_PORT = ROUTE[0]["port"]
CERT = "cert.pem"


async def handshake(ws):
    """Perform ECDH with node1, return (my_priv, session_key)."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    await ws.send(msgpack.packb(
        {"pub": pub.public_bytes(Encoding.Raw, PublicFormat.Raw)},
        use_bin_type=True
    ))
    raw = await ws.recv()
    resp = msgpack.unpackb(raw, raw=False)
    peer_pub = X25519PublicKey.from_public_bytes(bytes(resp["pub"]))
    shared = priv.exchange(peer_pub)
    return priv, derive_session_key(shared)


async def main():
    async with tls_in_tls_connect(NODE1_HOST, NODE1_PORT, cert=CERT) as raw_ws:
        ws = ShapedChannel(raw_ws, HTTPSBrowsingProfile)
        await ws.start()
        priv, session_key = await handshake(ws)
        session_id = secrets.randbits(32)

        # For onion we need both hop keys; in a full implementation each
        # hop's key is negotiated separately. Here we use the same key
        # for demonstration (replace with per-hop keys in production).
        route_keys = [session_key, session_key]

        app_data = b"Hello from onion client!"
        onion_frame = build_onion_packet(app_data, route_keys)

        # Start dummy traffic in background
        dummy_task = asyncio.ensure_future(
            run_dummy_sender(ws, route_keys)
        )

        await ws.send(onion_frame)
        print(f"[client] sent: {app_data}")

        try:
            raw_resp = await asyncio.wait_for(ws.recv(), timeout=10.0)
            plain = parse_frame(session_key, raw_resp)
            _, _, _, payload = unpack_plain(plain)
            print(f"[client] received: {payload}")
        except asyncio.TimeoutError:
            print("[client] timeout waiting for response")
        finally:
            dummy_task.cancel()
            await ws.stop()


if __name__ == "__main__":
    asyncio.run(main())
