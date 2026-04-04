"""
Unit tests for secure_tunnel.crypto

Tests:
  - derive_session_key with X25519 only
  - derive_session_key with X25519 + ML-KEM shared secret
  - mlkem_generate / mlkem_decapsulate roundtrip (if available)
  - Different inputs produce different keys
  - Same inputs always produce same key (deterministic via HKDF)
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secure_tunnel.crypto import (
    derive_session_key,
    HAS_MLKEM,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _x25519_shared() -> bytes:
    """Generate a random X25519 shared secret (32 bytes)."""
    priv_a = X25519PrivateKey.generate()
    priv_b = X25519PrivateKey.generate()
    return priv_a.exchange(priv_b.public_key())


class TestDeriveSessionKey(unittest.TestCase):

    def test_returns_32_bytes(self):
        key = derive_session_key(_x25519_shared())
        self.assertEqual(len(key), 32)

    def test_deterministic(self):
        shared = _x25519_shared()
        key1 = derive_session_key(shared)
        key2 = derive_session_key(shared)
        self.assertEqual(key1, key2)

    def test_different_x25519_different_keys(self):
        key1 = derive_session_key(_x25519_shared())
        key2 = derive_session_key(_x25519_shared())
        self.assertNotEqual(key1, key2)

    def test_with_mlkem_secret(self):
        mlkem_secret = os.urandom(32)
        key = derive_session_key(_x25519_shared(), mlkem_secret)
        self.assertEqual(len(key), 32)

    def test_mlkem_secret_changes_key(self):
        x_shared = _x25519_shared()
        key_without = derive_session_key(x_shared)
        key_with    = derive_session_key(x_shared, os.urandom(32))
        self.assertNotEqual(key_without, key_with)


class TestMLKEM(unittest.TestCase):

    @unittest.skipUnless(HAS_MLKEM, "ML-KEM not available in this cryptography build")
    def test_mlkem_roundtrip(self):
        from secure_tunnel.crypto import mlkem_generate, mlkem_encapsulate, mlkem_decapsulate
        priv, pub = mlkem_generate()
        ct, shared_enc = mlkem_encapsulate(pub)
        shared_dec = mlkem_decapsulate(priv, ct)
        self.assertEqual(shared_enc, shared_dec)

    @unittest.skipUnless(HAS_MLKEM, "ML-KEM not available in this cryptography build")
    def test_mlkem_different_keys(self):
        from secure_tunnel.crypto import mlkem_generate, mlkem_encapsulate
        _, pub = mlkem_generate()
        _, s1 = mlkem_encapsulate(pub)
        _, s2 = mlkem_encapsulate(pub)
        self.assertNotEqual(s1, s2)

    def test_has_mlkem_flag_is_bool(self):
        self.assertIsInstance(HAS_MLKEM, bool)


if __name__ == "__main__":
    unittest.main()
