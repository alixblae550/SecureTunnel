"""
Onion layer construction and peeling.

Client wraps payload in N layers (one per hop).
Each node peels its own layer and forwards the inner bytes.
"""
import os
import secrets
import msgpack

from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.protocol import pack_plain, unpack_plain, MSG_DATA


def build_onion_packet(app_data: bytes, route_session_keys: list) -> bytes:
    """
    Wrap app_data in len(route_session_keys) onion layers.
    route_session_keys[0] = key for first hop (node1)
    route_session_keys[-1] = key for exit node
    """
    sid = secrets.randbits(32)
    # innermost layer: actual data for exit
    payload = msgpack.packb({"final": True, "data": app_data}, use_bin_type=True)
    frame = build_frame(route_session_keys[-1], pack_plain(MSG_DATA, sid, 0, payload))

    # wrap in remaining layers from inside out
    for key in reversed(route_session_keys[:-1]):
        wrapper = msgpack.packb({"final": False, "data": frame}, use_bin_type=True)
        frame = build_frame(key, pack_plain(MSG_DATA, sid, 0, wrapper))

    return frame


def peel_onion_layer(session_key: bytes, frame: bytes):
    """
    Peel one onion layer.
    Returns (is_final: bool, inner_bytes: bytes)
    """
    plain = parse_frame(session_key, frame)
    _, _, _, payload = unpack_plain(plain)
    obj = msgpack.unpackb(payload, raw=False)
    return obj["final"], obj["data"]


def build_dummy_onion(route_session_keys: list) -> bytes:
    """Build a valid dummy onion packet (indistinguishable from real)."""
    dummy_data = os.urandom(32)
    return build_onion_packet(dummy_data, route_session_keys)
