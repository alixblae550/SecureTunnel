"""
Circuit rotation — controls when the relay tears down its current tunnel
connection and establishes a fresh one through the 3-node chain.

Rotation is triggered by whichever happens first:
  • TTL expires  (CIRCUIT_TTL_SECONDS, default 300 s)
  • Request count limit reached (CIRCUIT_MAX_REQUESTS, default 500)

Usage (from tunnel_relay.py):
    circuit = CircuitManager()
    ...
    circuit.on_request()        # call before each proxied request
    if circuit.should_rotate():
        await circuit.rotate(pool_drain_fn, pool_fill_fn)
"""

import asyncio
import time

from secure_tunnel.config import CIRCUIT_TTL_SECONDS, CIRCUIT_MAX_REQUESTS
from secure_tunnel.logging.anon_logger import log_event


class CircuitManager:
    """
    Tracks the age and request count of the current circuit.
    Thread-safe for single-event-loop async use.
    """

    def __init__(self):
        self._born_at: float = time.monotonic()
        self._requests: int = 0
        self._rotating: bool = False
        self._rotate_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # State queries
    # ------------------------------------------------------------------

    def age(self) -> float:
        """Seconds since this circuit was created."""
        return time.monotonic() - self._born_at

    def request_count(self) -> int:
        return self._requests

    def should_rotate(self) -> bool:
        """Return True if the circuit has exceeded TTL or request limit."""
        if self._rotating:
            return False
        if self.age() >= CIRCUIT_TTL_SECONDS:
            return True
        if self._requests >= CIRCUIT_MAX_REQUESTS:
            return True
        return False

    def on_request(self):
        """Must be called once per proxied request."""
        self._requests += 1

    # ------------------------------------------------------------------
    # Rotation
    # ------------------------------------------------------------------

    async def rotate(self, drain_fn, fill_fn) -> None:
        """
        Rotate the circuit:
          1. Drain the existing connection pool (drain_fn is a coroutine/callable
             that closes all pooled connections and clears the queue).
          2. Reset internal counters.
          3. Call fill_fn() to replenish the pool with fresh connections
             (goes through entry → middle → exit, establishing new K1/K2/K3).

        drain_fn and fill_fn must be async callables (coroutines).
        Only one rotation runs at a time; concurrent callers wait on the lock
        but skip the rotate if someone else already completed it.
        """
        async with self._rotate_lock:
            if not self.should_rotate():
                # Another coroutine already completed the rotation while we waited
                return

            self._rotating = True
            log_event("relay", 0, 0, 0,
                      f"circuit_rotate_start:age={self.age():.0f}s"
                      f":requests={self._requests}")

            try:
                await drain_fn()
                self._born_at = time.monotonic()
                self._requests = 0
                await fill_fn()
                log_event("relay", 0, 0, 0, "circuit_rotate_done")
            except Exception as e:
                log_event("relay", 0, 0, 0, f"circuit_rotate_error:{type(e).__name__}")
            finally:
                self._rotating = False

    def reset(self):
        """Hard reset without pool operations (e.g. at startup)."""
        self._born_at = time.monotonic()
        self._requests = 0
        self._rotating = False
