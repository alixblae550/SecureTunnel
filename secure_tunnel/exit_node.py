"""
Exit node — third and final hop in the 3-node circuit.

Circuit:  Relay  ──K1──►  Entry  ──K2──►  Middle  ──K3──►  Exit  ──►  Internet

Responsibilities
─────────────────
  • Accept TLS-in-TLS connections from the middle node (with anti-probing).
  • Receive CONNECT commands, resolve targets via DNS-over-HTTPS.
  • Relay data bidirectionally between the tunnel and the internet.
  • Reuse tunnel connections across multiple CONNECT sessions (connection reuse).
  • Handle RELAY_HANDSHAKE: generate ephemeral keys so the relay client can
    independently derive K3 (used for true onion routing via onion_client).

Security properties
────────────────────
  • Exit is the only node that knows the real destination host/port.
  • It does NOT know the relay's identity or IP address.
"""
import asyncio
import secrets
import socket

import msgpack
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.config import NODES
from secure_tunnel.transport.tls_in_tls_transport import tls_in_tls_serve
from secure_tunnel.keyring import load_or_generate
from secure_tunnel.doh_resolver import resolve as doh_resolve
from secure_tunnel.crypto import derive_session_key, mlkem_encapsulate
from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.protocol import pack_plain, unpack_plain, MSG_DATA, MSG_COVER, ReplayFilter
from secure_tunnel.logging.anon_logger import log_event

_exit_cfg = NODES["exit"]

HOST      = _exit_cfg["host"]
PORT      = _exit_cfg["port"]
NODE_NAME = "exit"
CERT      = "cert.pem"
KEY       = "key.pem"

_exit_priv, _exit_pub = load_or_generate(NODE_NAME)

_UDP_RECV_SIZE = 65535
_UDP_TIMEOUT   = 5.0   # seconds to wait for UDP response from destination


async def _handle_udp(ws, obj: dict, send_cmd) -> None:
    """
    Handle a single UDP datagram from the relay:
      1. Resolve hostname via DoH.
      2. Send the UDP payload to (host, port).
      3. Wait up to _UDP_TIMEOUT seconds for a response.
      4. Send UDP_RESP (or empty data on timeout/error) back through the tunnel.

    After this call the tunnel connection loops back and waits for the next
    CONNECT or UDP command — the connection is NOT closed.
    """
    host     = obj.get("host", "")
    port     = int(obj.get("port", 0))
    payload  = obj.get("data", b"")
    uid      = obj.get("id", 0)

    if isinstance(payload, memoryview):
        payload = bytes(payload)

    resp_data = b""
    loop = asyncio.get_event_loop()
    sock = None
    try:
        ip = await asyncio.wait_for(doh_resolve(host), timeout=3.0)
        is_ipv6 = ":" in ip
        family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        if len(payload) > 65507:
            payload = payload[:65507]
        addr = (ip, port, 0, 0) if is_ipv6 else (ip, port)
        await loop.sock_sendto(sock, payload, addr)
        recv_data, _ = await asyncio.wait_for(
            loop.sock_recvfrom(sock, _UDP_RECV_SIZE),
            timeout=_UDP_TIMEOUT,
        )
        resp_data = recv_data
        log_event(NODE_NAME, 0, MSG_DATA, len(resp_data), "udp_resp")
    except asyncio.TimeoutError:
        log_event(NODE_NAME, 0, 0, 0, "udp_timeout")
    except Exception as e:
        log_event(NODE_NAME, 0, 0, 0, f"udp_error:{type(e).__name__}")
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    try:
        await ws.send(send_cmd({"cmd": "UDP_RESP", "id": uid, "data": resp_data}))
    except Exception as e:
        log_event(NODE_NAME, 0, 0, 0, f"udp_resp_send_error:{type(e).__name__}")


async def _handle_relay_handshake(ws, session_key: bytes, session_id: int,
                                   send_cmd, obj: dict) -> None:
    """
    Handle RELAY_HANDSHAKE from middle on behalf of the relay client.
    Exit generates a fresh ephemeral key pair, performs ECDH with the
    client's public key, and sends back its ephemeral public key (and
    ML-KEM ciphertext if requested).  This allows the relay client to
    independently derive K3 for true onion routing.
    """
    client_x_pub = X25519PublicKey.from_public_bytes(bytes(obj["pub"]))

    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    mlkem_ct: bytes | None = None
    if obj.get("mlkem_pub"):
        mlkem_ct, _ = mlkem_encapsulate(bytes(obj["mlkem_pub"]))

    reply: dict = {"pub": eph_pub_bytes}
    if mlkem_ct is not None:
        reply["mlkem_ct"] = mlkem_ct
    await ws.send(send_cmd(reply))
    log_event(NODE_NAME, session_id, 0, 0, "relay_handshake_ok")


async def handler(ws):
    """
    Handle one middle-node tunnel connection.
    ws = TlsInTlsChannel already auth-checked by the transport layer.
    """
    hop_id     = NODE_NAME
    session_id = secrets.randbits(32)

    # ── Hybrid ECDH handshake with middle (K3) ───────────────────────────────
    raw   = await ws.recv()
    hello = msgpack.unpackb(raw, raw=False)
    peer_pub  = X25519PublicKey.from_public_bytes(bytes(hello["pub"]))
    x25519_ss = _exit_priv.exchange(peer_pub)

    mlkem_ct_:  bytes | None = None
    mlkem_ss_:  bytes | None = None
    if hello.get("mlkem_pub"):
        mlkem_ct_, mlkem_ss_ = mlkem_encapsulate(bytes(hello["mlkem_pub"]))

    session_key = derive_session_key(x25519_ss, mlkem_ss_)   # K3

    reply: dict = {"pub": _exit_pub.public_bytes(Encoding.Raw, PublicFormat.Raw)}
    if mlkem_ct_ is not None:
        reply["mlkem_ct"] = mlkem_ct_
    await ws.send(msgpack.packb(reply, use_bin_type=True))

    _seq_out: list[int] = [0]
    _in_filter = ReplayFilter()

    def _send_cmd(obj: dict) -> bytes:
        payload = msgpack.packb(obj, use_bin_type=True)
        frame = build_frame(session_key, pack_plain(MSG_DATA, session_id, _seq_out[0], payload))
        _seq_out[0] = (_seq_out[0] + 1) & 0xFFFF_FFFF
        return frame

    def _parse_cmd(raw_frame: bytes) -> dict:
        plain = parse_frame(session_key, raw_frame)
        msg_type, _, seq, payload = unpack_plain(plain)
        if not _in_filter.accept(seq):
            raise ValueError(f"replay_drop:seq={seq}")
        if msg_type == MSG_COVER:
            return {"cmd": "COVER"}
        return msgpack.unpackb(payload, raw=False)

    # ── Session loop: one tunnel connection handles CONNECT and UDP commands ─────
    while True:
        # Drain leftover frames from the previous session, wait for next command
        while True:
            try:
                raw_frame = await ws.recv()
            except ConnectionError:
                return
            try:
                obj = _parse_cmd(raw_frame)
            except Exception:
                continue
            cmd = obj.get("cmd")
            if cmd == "CONNECT":
                break
            if cmd == "UDP":
                await _handle_udp(ws, obj, _send_cmd)
                # Loop back — connection stays alive for the next command
                continue
            if cmd == "RELAY_HANDSHAKE":
                await _handle_relay_handshake(ws, session_key, session_id, _send_cmd, obj)
                continue
            # CLOSE / COVER / other cleanup frames — discard

        host = obj["host"]
        port = obj["port"]
        log_event(hop_id, session_id, MSG_DATA, 0, "connect")

        # ── Connect to target ─────────────────────────────────────────────────
        try:
            ip = await asyncio.wait_for(doh_resolve(host), timeout=5.0)
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, family=family), timeout=10.0
            )
            log_event(hop_id, session_id, MSG_DATA, 0, "connect_ok")
            await ws.send(_send_cmd({"cmd": "CONNECT_OK"}))
        except Exception as e:
            log_event(hop_id, session_id, 0, 0, f"connect_err:{type(e).__name__}")
            try:
                await ws.send(_send_cmd({"cmd": "CONNECT_ERR", "msg": str(e)}))
            except Exception:
                return
            continue  # keep tunnel alive — wait for next CONNECT

        # ── Bidirectional relay ───────────────────────────────────────────────
        stop_event = asyncio.Event()

        async def target_to_tunnel():
            try:
                while not stop_event.is_set():
                    data = await target_reader.read(65536)
                    if not data:
                        break
                    log_event(hop_id, session_id, MSG_DATA, len(data), "out")
                    await ws.send(_send_cmd({"cmd": "DATA", "data": data}))
            except (OSError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                log_event("exit", session_id, 0, 0, f"target_tunnel_error:{type(e).__name__}")
            finally:
                stop_event.set()
                try:
                    await ws.send(_send_cmd({"cmd": "CLOSE"}))
                except Exception:
                    pass

        async def tunnel_to_target():
            try:
                async for raw_frame in ws:
                    if stop_event.is_set():
                        break
                    try:
                        obj = _parse_cmd(raw_frame)
                        cmd = obj.get("cmd")
                        if cmd == "COVER":
                            continue  # discard cover-traffic frames
                        elif cmd == "DATA":
                            data = obj.get("data", b"")
                            target_writer.write(
                                bytes(data) if not isinstance(data, bytes) else data
                            )
                            await target_writer.drain()
                            log_event(hop_id, session_id, MSG_DATA, len(data), "in")
                        elif cmd == "CLOSE":
                            break
                    except Exception as e:
                        log_event("exit", session_id, 0, 0, f"tunnel_parse_error:{type(e).__name__}")
                        break
            except (OSError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as e:
                log_event("exit", session_id, 0, 0, f"tunnel_target_error:{type(e).__name__}")
            finally:
                stop_event.set()

        await asyncio.gather(target_to_tunnel(), tunnel_to_target())

        try:
            target_writer.close()
            await target_writer.wait_closed()
        except Exception:
            pass
        # Do NOT close ws — loop back for the next CONNECT


async def main():
    def _on_ready():
        print(f"[exit] listening on {HOST}:{PORT} (TLS-in-TLS, DoH, anti-probing)", flush=True)

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
