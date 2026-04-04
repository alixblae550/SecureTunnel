"""
Key exchange interfaces and implementations.

Includes:
  - KeyExchange (abstract base)
  - X25519KeyExchange
  - HybridKeyExchange (X25519 + PQ-KEM stub)
"""
from abc import ABC, abstractmethod

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

from secure_tunnel.crypto import derive_session_key


class KeyExchange(ABC):
    @abstractmethod
    def generate_keypair(self):
        """Returns (private_key, public_key)"""

    @abstractmethod
    def serialize_public(self, pub) -> bytes:
        ...

    @abstractmethod
    def deserialize_public(self, data: bytes):
        ...

    @abstractmethod
    def derive_shared(self, priv, peer_pub) -> bytes:
        ...


class X25519KeyExchange(KeyExchange):
    def generate_keypair(self):
        priv = X25519PrivateKey.generate()
        return priv, priv.public_key()

    def serialize_public(self, pub: X25519PublicKey) -> bytes:
        return pub.public_bytes(Encoding.Raw, PublicFormat.Raw)

    def deserialize_public(self, data: bytes) -> X25519PublicKey:
        return X25519PublicKey.from_public_bytes(data)

    def derive_shared(self, priv: X25519PrivateKey, peer_pub: X25519PublicKey) -> bytes:
        return priv.exchange(peer_pub)


class PQKeyExchangeStub(KeyExchange):
    """
    Stub for post-quantum KEM (e.g. Kyber).
    Replace the methods with a real PQ library (e.g. liboqs-python).
    """
    def generate_keypair(self):
        import os
        # Placeholder: random 32-byte keys
        priv = os.urandom(32)
        pub = os.urandom(32)
        return priv, pub

    def serialize_public(self, pub: bytes) -> bytes:
        return pub

    def deserialize_public(self, data: bytes) -> bytes:
        return data

    def derive_shared(self, priv: bytes, peer_pub: bytes) -> bytes:
        # Placeholder: XOR (NOT secure, replace with real KEM)
        return bytes(a ^ b for a, b in zip(priv, peer_pub))


class HybridKeyExchange:
    """
    Hybrid key exchange: X25519 + PQ-KEM.
    The session key is derived from the concatenated shared secrets.
    """
    def __init__(self, classical: KeyExchange = None, pq: KeyExchange = None):
        self.classical = classical or X25519KeyExchange()
        self.pq = pq or PQKeyExchangeStub()

    def generate_keypair(self):
        c_priv, c_pub = self.classical.generate_keypair()
        p_priv, p_pub = self.pq.generate_keypair()
        return (c_priv, p_priv), (c_pub, p_pub)

    def serialize_public(self, pub_pair) -> bytes:
        c_pub, p_pub = pub_pair
        c_bytes = self.classical.serialize_public(c_pub)
        p_bytes = self.pq.serialize_public(p_pub)
        import struct
        return struct.pack("!HH", len(c_bytes), len(p_bytes)) + c_bytes + p_bytes

    def deserialize_public(self, data: bytes):
        import struct
        c_len, p_len = struct.unpack("!HH", data[:4])
        c_bytes = data[4:4 + c_len]
        p_bytes = data[4 + c_len:4 + c_len + p_len]
        return self.classical.deserialize_public(c_bytes), self.pq.deserialize_public(p_bytes)

    def derive_session_key(self, priv_pair, peer_pub_pair) -> bytes:
        c_priv, p_priv = priv_pair
        c_pub, p_pub = peer_pub_pair
        s1 = self.classical.derive_shared(c_priv, c_pub)
        s2 = self.pq.derive_shared(p_priv, p_pub)
        return derive_session_key(s1 + s2)
