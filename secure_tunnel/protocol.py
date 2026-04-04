"""
Wire protocol: msgpack-packed frames with message type, session ID, sequence
number, and payload.

Sequence number validation (replay protection):
  ReplayFilter tracks the highest seen seq_no per session.  Frames with
  seq_no ≤ last seen are dropped (replays or severe reordering).  A ±32-frame
  window tolerates minor packet reordering while blocking replay attacks.

  Note: seq_no is a 32-bit integer that wraps around.  The filter handles
  wrap-around correctly using modular arithmetic.
"""
import msgpack

MSG_DUMMY   = 0
MSG_DATA    = 1
MSG_CONTROL = 2
MSG_COVER   = 3   # cover-traffic frame — random payload, discarded by receiver

_SEQ_WINDOW = 64   # frames within this range of the head are accepted


def pack_plain(msg_type: int, session_id: int, seq_no: int, payload: bytes) -> bytes:
    obj = {"t": msg_type, "sid": session_id, "seq": seq_no, "p": payload}
    return msgpack.packb(obj, use_bin_type=True)


def unpack_plain(data: bytes):
    obj = msgpack.unpackb(data, raw=False)
    return obj["t"], obj["sid"], obj["seq"], obj["p"]


class ReplayFilter:
    """
    Per-session sequence number replay filter.

    Accepts frames with seq_no in (last_seq - _SEQ_WINDOW, last_seq + ∞).
    Rejects frames with seq_no ≤ last_seq - _SEQ_WINDOW (replay / severe
    reordering).  Does NOT enforce strict ordering — out-of-order delivery
    within the window is accepted to accommodate jitter.

    Usage:
        rf = ReplayFilter()
        if rf.accept(seq_no):
            # process frame
        else:
            # drop (replay or too old)
    """

    def __init__(self) -> None:
        self._head: int | None = None   # highest accepted seq_no so far
        self._seen: set[int] = set()    # set of accepted seq_nos in window

    def accept(self, seq_no: int) -> bool:
        """Return True if seq_no should be processed, False if it should be dropped."""
        if self._head is None:
            # First frame — always accept
            self._head = seq_no
            self._seen.add(seq_no)
            return True

        # Exact duplicate
        if seq_no in self._seen:
            return False

        # Too old (replay)
        delta = (seq_no - self._head) & 0xFFFF_FFFF   # unsigned 32-bit difference
        if delta > 0x8000_0000:
            # seq_no is behind head (negative delta in signed arithmetic)
            behind = (self._head - seq_no) & 0xFFFF_FFFF
            if behind > _SEQ_WINDOW:
                return False  # replay: too old

        # Accept and advance window
        self._seen.add(seq_no)
        # Advance head
        signed_delta = delta if delta <= 0x7FFF_FFFF else delta - 0x1_0000_0000
        if signed_delta > 0:
            self._head = seq_no
        # Evict entries that are now outside the window
        cutoff = (self._head - _SEQ_WINDOW) & 0xFFFF_FFFF
        self._seen = {s for s in self._seen
                      if ((s - cutoff) & 0xFFFF_FFFF) <= _SEQ_WINDOW * 2}
        return True

    def reset(self) -> None:
        """Reset state (e.g. after circuit rotation)."""
        self._head = None
        self._seen.clear()
