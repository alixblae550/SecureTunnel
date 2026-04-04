"""
Framing — encrypt, pad, and frame messages for tunnel transport.

Padding strategy: bucket padding
  Every encrypted frame is padded UP to the next boundary in PADDING_BUCKETS
  (256 / 512 / 768 / 1024 / 1536 / 2048 / 3072 / 4096 / 6144 / 8192 / 12288 / 16384 bytes).
  12 bucket sizes produce a smooth, natural-looking packet-size histogram that
  resembles real HTTPS traffic — making traffic-analysis size fingerprinting useless.

Wire format:
  [4B total_padded_len][4B real_ct_len][ciphertext][random padding]

  total_padded_len — length of the data after the two 4-byte headers
  real_ct_len      — length of the actual ciphertext (≤ total_padded_len)

Cover-traffic frames (CMD_COVER):
  Constructed identically to real frames but carry a random payload.
  The receiver strips them after decryption by checking the msgpack command.
"""
import os
import struct

from secure_tunnel.config import PADDING_BUCKETS
from secure_tunnel.crypto import encrypt_message, decrypt_message


def _next_bucket(n: int) -> int:
    """Return the smallest bucket size ≥ n, or n itself if it exceeds all buckets."""
    for b in PADDING_BUCKETS:
        if n <= b:
            return b
    return n  # oversized frame: no padding, avoid negative pad_len


def build_frame(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext, pad to the next bucket boundary.

    Returns: [4B padded_len][4B real_ct_len][ciphertext + random_padding]
    """
    ct = encrypt_message(key, plaintext)
    real_len = len(ct)
    target = _next_bucket(real_len)
    pad_len = target - real_len
    padded = ct + os.urandom(pad_len)
    return struct.pack("!II", target, real_len) + padded


def parse_frame(key: bytes, frame: bytes) -> bytes:
    """
    Strip padding, decrypt and return plaintext.
    Raises ValueError on malformed frames, cryptography errors bubble up.
    """
    if len(frame) < 8:
        raise ValueError("frame too small")
    total_len, real_len = struct.unpack("!II", frame[:8])
    if real_len > total_len:
        raise ValueError("real_len exceeds total_len")
    if len(frame) < 8 + total_len:
        raise ValueError(f"frame truncated: have {len(frame)}, need {8 + total_len}")
    ct = frame[8:8 + real_len]
    return decrypt_message(key, ct)
