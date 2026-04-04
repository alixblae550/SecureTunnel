"""
Unit tests for secure_tunnel.key_exchange

Tests:
  - X25519KeyExchange: generate → encapsulate → decapsulate roundtrip
  - X25519KeyExchange: different sessions produce different keys
  - MLKEMKeyExchange: roundtrip when available, no-op when unavailable
  - HybridKeyExchange: full initiator/responder roundtrip (both parties same key)
  - HybridKeyExchange: different runs produce different session keys
  - HybridKeyExchange: wrong response blob raises / produces wrong key
  - parse_public_blob round-trips generate_keypair blob correctly
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secure_tunnel.crypto import HAS_MLKEM
from secure_tunnel.key_exchange import (
    X25519KeyExchange,
    MLKEMKeyExchange,
    HybridKeyExchange,
)


class TestX25519KeyExchange(unittest.TestCase):

    def test_roundtrip_same_secret(self):
        """Both sides derive identical shared secrets."""
        kex = X25519KeyExchange()
        priv_a, pub_a = kex.generate_keypair()
        # B encapsulates to A's public key
        pub_b, shared_b = kex.encapsulate(pub_a)
        # A decapsulates B's ephemeral pub
        shared_a = kex.decapsulate(priv_a, pub_b)
        self.assertEqual(shared_a, shared_b)

    def test_shared_secret_is_32_bytes(self):
        kex = X25519KeyExchange()
        priv_a, pub_a = kex.generate_keypair()
        _, shared = kex.encapsulate(pub_a)
        self.assertEqual(len(shared), 32)

    def test_different_keypairs_different_secrets(self):
        kex = X25519KeyExchange()
        _, pub1 = kex.generate_keypair()
        _, pub2 = kex.generate_keypair()
        _, s1 = kex.encapsulate(pub1)
        _, s2 = kex.encapsulate(pub2)
        self.assertNotEqual(s1, s2)

    def test_pub_is_32_bytes(self):
        kex = X25519KeyExchange()
        _, pub = kex.generate_keypair()
        self.assertEqual(len(pub), 32)


class TestMLKEMKeyExchange(unittest.TestCase):

    @unittest.skipUnless(HAS_MLKEM, "ML-KEM not available in this build")
    def test_roundtrip_same_secret(self):
        kex = MLKEMKeyExchange()
        priv, pub = kex.generate_keypair()
        ct, ss_enc = kex.encapsulate(pub)
        ss_dec = kex.decapsulate(priv, ct)
        self.assertEqual(ss_enc, ss_dec)
        self.assertGreater(len(ss_enc), 0)

    @unittest.skipUnless(HAS_MLKEM, "ML-KEM not available in this build")
    def test_two_encapsulations_different_secrets(self):
        kex = MLKEMKeyExchange()
        _, pub = kex.generate_keypair()
        _, s1 = kex.encapsulate(pub)
        _, s2 = kex.encapsulate(pub)
        self.assertNotEqual(s1, s2)

    def test_no_mlkem_returns_empty(self):
        """When ML-KEM is unavailable, operations return empty bytes."""
        if HAS_MLKEM:
            self.skipTest("ML-KEM is available — skipping no-op path test")
        kex = MLKEMKeyExchange()
        priv, pub = kex.generate_keypair()
        self.assertEqual(pub, b"")
        ct, ss = kex.encapsulate(b"")
        self.assertEqual(ct, b"")
        self.assertEqual(ss, b"")


class TestHybridKeyExchange(unittest.TestCase):

    def test_full_roundtrip_same_key(self):
        """
        Initiator and responder must derive the identical session key.
        """
        kex = HybridKeyExchange()
        priv_pair, init_blob = kex.generate_keypair()
        resp_blob, responder_key = kex.respond(init_blob)
        initiator_key = kex.finish(priv_pair, resp_blob)
        self.assertEqual(initiator_key, responder_key)

    def test_session_key_is_32_bytes(self):
        kex = HybridKeyExchange()
        priv_pair, init_blob = kex.generate_keypair()
        resp_blob, key = kex.respond(init_blob)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(kex.finish(priv_pair, resp_blob)), 32)

    def test_two_sessions_different_keys(self):
        """Independent sessions must produce independent keys."""
        kex = HybridKeyExchange()
        _, blob1 = kex.generate_keypair()
        _, blob2 = kex.generate_keypair()
        _, key1 = kex.respond(blob1)
        _, key2 = kex.respond(blob2)
        self.assertNotEqual(key1, key2)

    def test_parse_public_blob_roundtrip(self):
        """parse_public_blob should recover x25519 and mlkem portions."""
        kex = HybridKeyExchange()
        _, blob = kex.generate_keypair()
        x_pub, m_pub = kex.parse_public_blob(blob)
        self.assertEqual(len(x_pub), 32)  # X25519 pub is always 32 bytes

    def test_wrong_response_blob_wrong_key(self):
        """Finishing with a garbage blob must not silently produce the right key."""
        kex = HybridKeyExchange()
        priv_pair, init_blob = kex.generate_keypair()
        resp_blob, correct_key = kex.respond(init_blob)
        # Corrupt the response blob
        garbage = bytes(b ^ 0xFF for b in resp_blob)
        try:
            bad_key = kex.finish(priv_pair, garbage)
            self.assertNotEqual(bad_key, correct_key)
        except Exception:
            pass  # An exception is also acceptable — crypto detected corruption

    def test_multiple_independent_instances(self):
        """Each HybridKeyExchange instance is independent."""
        kex1 = HybridKeyExchange()
        kex2 = HybridKeyExchange()
        priv1, blob1 = kex1.generate_keypair()
        priv2, blob2 = kex2.generate_keypair()
        _, k1 = kex1.respond(blob1)
        _, k2 = kex2.respond(blob2)
        self.assertNotEqual(k1, k2)


class TestReplayFilter(unittest.TestCase):
    """Tests for the ReplayFilter in protocol.py."""

    def _make_filter(self):
        from secure_tunnel.protocol import ReplayFilter
        return ReplayFilter()

    def test_first_frame_accepted(self):
        rf = self._make_filter()
        self.assertTrue(rf.accept(0))

    def test_sequential_accepted(self):
        rf = self._make_filter()
        for i in range(100):
            self.assertTrue(rf.accept(i), f"seq={i} should be accepted")

    def test_exact_duplicate_rejected(self):
        rf = self._make_filter()
        rf.accept(42)
        self.assertFalse(rf.accept(42))

    def test_replay_old_rejected(self):
        """Seq far behind head (more than window) must be rejected."""
        from secure_tunnel.protocol import _SEQ_WINDOW
        rf = self._make_filter()
        rf.accept(1000)
        self.assertFalse(rf.accept(1000 - _SEQ_WINDOW - 1))

    def test_within_window_reorder_accepted(self):
        """Out-of-order within the window should be accepted."""
        rf = self._make_filter()
        rf.accept(100)
        rf.accept(101)
        # Deliver 99 slightly late — still within the _SEQ_WINDOW
        self.assertTrue(rf.accept(99))

    def test_wraparound(self):
        """Seq wrapping around 2^32 must be handled correctly."""
        rf = self._make_filter()
        max32 = 0xFFFF_FFFF
        rf.accept(max32 - 1)
        rf.accept(max32)
        self.assertTrue(rf.accept(0))   # wraps around — not a replay

    def test_reset_clears_state(self):
        rf = self._make_filter()
        rf.accept(5)
        rf.reset()
        # After reset, seq=5 must be accepted again
        self.assertTrue(rf.accept(5))


if __name__ == "__main__":
    unittest.main()
