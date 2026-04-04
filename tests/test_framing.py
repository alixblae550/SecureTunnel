"""
Unit tests for secure_tunnel.framing

Tests:
  - build_frame / parse_frame roundtrip for various payload sizes
  - Framed size is always aligned to a padding bucket
  - Oversized payloads (> 16384) are passed without padding
  - parse_frame recovers exact original payload
  - Empty payload works
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from secure_tunnel.framing import build_frame, parse_frame
from secure_tunnel.config import PADDING_BUCKETS


def _make_key() -> bytes:
    return os.urandom(32)


class TestFramingRoundtrip(unittest.TestCase):

    def _roundtrip(self, payload: bytes):
        key = _make_key()
        frame = build_frame(key, payload)
        recovered = parse_frame(key, frame)
        self.assertEqual(recovered, payload)

    def test_small_payload(self):
        self._roundtrip(b"hello")

    def test_empty_payload(self):
        self._roundtrip(b"")

    def test_exact_bucket_boundary(self):
        for size in PADDING_BUCKETS:
            with self.subTest(size=size):
                self._roundtrip(os.urandom(size))

    def test_just_under_bucket(self):
        for size in PADDING_BUCKETS:
            with self.subTest(size=size - 1):
                self._roundtrip(os.urandom(max(0, size - 1)))

    def test_large_payload(self):
        # Larger than max bucket — no padding
        self._roundtrip(os.urandom(32768))

    def test_random_sizes(self):
        import random
        for _ in range(20):
            size = random.randint(0, 20000)
            self._roundtrip(os.urandom(size))


class TestFramingPadding(unittest.TestCase):

    def test_frame_size_is_bucket_aligned(self):
        """Framed ciphertext length should equal one of the bucket sizes (for small payloads)."""
        key = _make_key()
        for payload_size in [1, 100, 500, 1000, 2000, 4000]:
            payload = os.urandom(payload_size)
            frame = build_frame(key, payload)
            # frame = [4B padded_len][4B real_ct_len][data]
            import struct
            padded_len = struct.unpack("!I", frame[:4])[0]
            self.assertIn(padded_len, PADDING_BUCKETS,
                          f"payload_size={payload_size}: padded_len={padded_len} not in buckets")

    def test_oversized_no_crash(self):
        """Payloads larger than max bucket should not crash."""
        key = _make_key()
        payload = os.urandom(PADDING_BUCKETS[-1] + 1)
        frame = build_frame(key, payload)
        recovered = parse_frame(key, frame)
        self.assertEqual(recovered, payload)

    def test_wrong_key_raises(self):
        """Decrypting with wrong key should raise an exception."""
        key1 = _make_key()
        key2 = _make_key()
        frame = build_frame(key1, b"secret data")
        with self.assertRaises(Exception):
            parse_frame(key2, frame)


if __name__ == "__main__":
    unittest.main()
