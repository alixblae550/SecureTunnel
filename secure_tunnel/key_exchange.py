"""
Key exchange interfaces and implementations.

Includes:
  - KeyExchange (abstract base)
  - X25519KeyExchange
  - MLKEMKeyExchange  — ML-KEM-768 (post-quantum), falls back to no-op when
                        cryptography is built against OpenSSL < 3.5
  - HybridKeyExchange — X25519 + ML-KEM-768 combined; derives the session key
                        from the concatenation of both shared secrets via HKDF
"""
import struct
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from secure_tunnel.crypto import derive_session_key, HAS_MLKEM


class KeyExchange(ABC):
    @abstractmethod
    def generate_keypair(self):
        """Returns (private_key, public_key_bytes)."""

    @abstractmethod
    def encapsulate(self, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret)."""

    @abstractmethod
    def decapsulate(self, priv, ciphertext: bytes) -> bytes:
        """Returns shared_secret."""


class X25519KeyExchange(KeyExchange):
    """Classical Diffie-Hellman over Curve25519."""

    def generate_keypair(self) -> tuple:
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        return priv, pub_bytes

    def encapsulate(self, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """
        X25519 encapsulate: generate ephemeral key, perform DH.
        Returns (own_pub_bytes, shared_secret).  The "ciphertext" here is
        the ephemeral public key the peer needs to complete the exchange.
        """
        priv = X25519PrivateKey.generate()
        pub_bytes = priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared = priv.exchange(peer_pub)
        return pub_bytes, shared

    def decapsulate(self, priv: X25519PrivateKey, peer_pub_bytes: bytes) -> bytes:
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        return priv.exchange(peer_pub)


class MLKEMKeyExchange(KeyExchange):
    """
    ML-KEM-768 post-quantum KEM.

    Available only when the installed `cryptography` package is built against
    OpenSSL >= 3.5 (HAS_MLKEM == True).  When unavailable all operations
    return empty bytes so callers can detect the no-op and skip PQ material.
    """

    def generate_keypair(self) -> tuple:
        if not HAS_MLKEM:
            return None, b""
        from secure_tunnel.crypto import mlkem_generate
        priv, pub_bytes = mlkem_generate()
        return priv, pub_bytes or b""

    def encapsulate(self, peer_pub_bytes: bytes) -> tuple[bytes, bytes]:
        """Returns (ciphertext, shared_secret), or (b"", b"") when unavailable."""
        if not HAS_MLKEM or not peer_pub_bytes:
            return b"", b""
        from secure_tunnel.crypto import mlkem_encapsulate
        ct, ss = mlkem_encapsulate(peer_pub_bytes)
        return ct or b"", ss or b""

    def decapsulate(self, priv, ciphertext: bytes) -> bytes:
        """Returns shared_secret, or b"" when unavailable."""
        if not HAS_MLKEM or priv is None or not ciphertext:
            return b""
        from secure_tunnel.crypto import mlkem_decapsulate
        ss = mlkem_decapsulate(priv, ciphertext)
        return ss or b""


class HybridKeyExchange:
    """
    Hybrid key exchange: X25519 + ML-KEM-768.

    Wire format for the combined public key blob:
        [2B x25519_len][2B mlkem_len][x25519_pub][mlkem_pub]

    The session key is derived via HKDF from:
        x25519_shared_secret || mlkem_shared_secret
    (mlkem portion is empty bytes when ML-KEM is unavailable — HKDF still
    produces a unique key from x25519 alone in that case.)
    """

    def __init__(self):
        self.classical = X25519KeyExchange()
        self.pq = MLKEMKeyExchange()

    # ------------------------------------------------------------------
    # Initiator side (e.g. relay / onion client)
    # ------------------------------------------------------------------

    def generate_keypair(self) -> tuple[tuple, bytes]:
        """
        Generate an initiator keypair.
        Returns ((x25519_priv, mlkem_priv), serialized_public_blob).
        """
        x_priv, x_pub = self.classical.generate_keypair()
        m_priv, m_pub = self.pq.generate_keypair()
        blob = struct.pack("!HH", len(x_pub), len(m_pub)) + x_pub + m_pub
        return (x_priv, m_priv), blob

    def parse_public_blob(self, blob: bytes) -> tuple[bytes, bytes]:
        """Split a blob created by generate_keypair into (x25519_pub, mlkem_pub)."""
        x_len, m_len = struct.unpack("!HH", blob[:4])
        x_pub = blob[4: 4 + x_len]
        m_pub = blob[4 + x_len: 4 + x_len + m_len]
        return x_pub, m_pub

    # ------------------------------------------------------------------
    # Responder side (e.g. entry / middle / exit node)
    # ------------------------------------------------------------------

    def respond(self, initiator_blob: bytes) -> tuple[bytes, bytes]:
        """
        Given the initiator's public blob, produce:
          - response_blob  — to be sent back to the initiator
          - session_key    — 32-byte key derived from both shared secrets

        response_blob wire format:
            [2B x_resp_len][2B mlkem_ct_len][x_resp][mlkem_ct]
        """
        x_pub, m_pub = self.parse_public_blob(initiator_blob)

        # X25519: ephemeral response key + DH
        x_resp_pub, x_ss = self.classical.encapsulate(x_pub)

        # ML-KEM: encapsulate with initiator's public key
        m_ct, m_ss = self.pq.encapsulate(m_pub)

        resp_blob = struct.pack("!HH", len(x_resp_pub), len(m_ct)) + x_resp_pub + m_ct
        session_key = derive_session_key(x_ss, m_ss if m_ss else None)
        return resp_blob, session_key

    def finish(self, priv_pair: tuple, response_blob: bytes) -> bytes:
        """
        Initiator completes the exchange given the responder's blob.
        Returns the 32-byte session key.
        """
        x_priv, m_priv = priv_pair
        x_resp_len, m_ct_len = struct.unpack("!HH", response_blob[:4])
        x_resp_pub = response_blob[4: 4 + x_resp_len]
        m_ct       = response_blob[4 + x_resp_len: 4 + x_resp_len + m_ct_len]

        x_ss = self.classical.decapsulate(x_priv, x_resp_pub)
        m_ss = self.pq.decapsulate(m_priv, m_ct)
        return derive_session_key(x_ss, m_ss if m_ss else None)
