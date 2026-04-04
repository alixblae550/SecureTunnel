"""
Unit tests for secure_tunnel.anti_probing

Tests:
  - server_challenge / client_respond HMAC roundtrip (correct secret passes)
  - Wrong secret is rejected
  - Truncated response is rejected
  - Empty response is rejected
  - check_rate allows loopback unconditionally
  - check_rate blocks IPs that exceed the window
  - check_rate allows IPs within the window
"""
import asyncio
import hashlib
import hmac
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Minimal in-memory channel stub for testing the HMAC protocol
# ---------------------------------------------------------------------------

class _FakeChannel:
    """Pairs two channels so send() from one appears in recv() of the other."""

    def __init__(self):
        self._q: asyncio.Queue = None  # set by _make_pair

    async def send(self, data: bytes) -> None:
        await self._q.put(data)

    async def recv(self) -> bytes:
        return await self._q.get()


def _make_pair():
    """Return (server_channel, client_channel) connected in-memory."""
    s_to_c: asyncio.Queue = asyncio.Queue()
    c_to_s: asyncio.Queue = asyncio.Queue()

    server = _FakeChannel()
    client = _FakeChannel()

    # server sends → client receives via s_to_c
    # client sends → server receives via c_to_s
    server._send_q = s_to_c
    client._recv_q = s_to_c
    server._recv_q = c_to_s
    client._send_q = c_to_s

    async def _server_send(data):
        await s_to_c.put(data)

    async def _server_recv():
        return await c_to_s.get()

    async def _client_send(data):
        await c_to_s.put(data)

    async def _client_recv():
        return await s_to_c.get()

    server.send = _server_send
    server.recv = _server_recv
    client.send = _client_send
    client.recv = _client_recv
    return server, client


# ---------------------------------------------------------------------------
# HMAC challenge-response tests
# ---------------------------------------------------------------------------

class TestHMACChallenge(unittest.TestCase):

    def _run(self, coro):
        return asyncio.run(coro)

    def test_correct_secret_passes(self):
        """server_challenge + client_respond with same secret → True."""
        import secure_tunnel.anti_probing as ap

        async def _scenario():
            server, client = _make_pair()
            result_box = [None]

            async def server_side():
                result_box[0] = await ap.server_challenge(server)

            async def client_side():
                await ap.client_respond(client)

            await asyncio.gather(server_side(), client_side())
            return result_box[0]

        result = self._run(_scenario())
        self.assertTrue(result)

    def test_wrong_secret_rejected(self):
        """Manually send HMAC with wrong key — server must reject."""
        import secure_tunnel.anti_probing as ap

        async def _scenario():
            server, client = _make_pair()
            result_box = [None]

            async def server_side():
                result_box[0] = await ap.server_challenge(server)

            async def bad_client():
                nonce = await client.recv()
                # Respond with HMAC computed from the WRONG key
                bad_response = hmac.new(b"wrong-key", nonce, hashlib.sha256).digest()
                await client.send(bad_response)

            await asyncio.gather(server_side(), bad_client())
            return result_box[0]

        result = self._run(_scenario())
        self.assertFalse(result)

    def test_truncated_response_rejected(self):
        """Response shorter than 32 bytes is rejected."""
        import secure_tunnel.anti_probing as ap

        async def _scenario():
            server, client = _make_pair()
            result_box = [None]

            async def server_side():
                result_box[0] = await ap.server_challenge(server)

            async def short_client():
                _nonce = await client.recv()
                await client.send(b"\x00" * 16)   # only 16 bytes, not 32

            await asyncio.gather(server_side(), short_client())
            return result_box[0]

        result = self._run(_scenario())
        self.assertFalse(result)

    def test_empty_response_rejected(self):
        """Empty response is rejected."""
        import secure_tunnel.anti_probing as ap

        async def _scenario():
            server, client = _make_pair()
            result_box = [None]

            async def server_side():
                result_box[0] = await ap.server_challenge(server)

            async def empty_client():
                _nonce = await client.recv()
                await client.send(b"")

            await asyncio.gather(server_side(), empty_client())
            return result_box[0]

        result = self._run(_scenario())
        self.assertFalse(result)


# ---------------------------------------------------------------------------
# Rate limiting tests
# ---------------------------------------------------------------------------

class TestRateLimit(unittest.TestCase):

    def setUp(self):
        # Clear the global rate table before each test
        import secure_tunnel.anti_probing as ap
        ap._rate_table.clear()

    def test_loopback_always_allowed(self):
        from secure_tunnel.anti_probing import check_rate
        for _ in range(200):
            self.assertTrue(check_rate("127.0.0.1"))

    def test_ipv6_loopback_always_allowed(self):
        from secure_tunnel.anti_probing import check_rate
        for _ in range(200):
            self.assertTrue(check_rate("::1"))

    def test_first_connection_allowed(self):
        from secure_tunnel.anti_probing import check_rate
        self.assertTrue(check_rate("10.0.0.1"))

    def test_within_limit_allowed(self):
        from secure_tunnel.anti_probing import check_rate
        from secure_tunnel.config import RATE_LIMIT_PER_MIN
        ip = "192.168.1.50"
        for i in range(RATE_LIMIT_PER_MIN):
            self.assertTrue(check_rate(ip), f"connection {i+1} should be allowed")

    def test_exceeding_limit_blocked(self):
        from secure_tunnel.anti_probing import check_rate
        from secure_tunnel.config import RATE_LIMIT_PER_MIN
        ip = "192.168.1.99"
        for _ in range(RATE_LIMIT_PER_MIN):
            check_rate(ip)
        # The next one must be blocked
        self.assertFalse(check_rate(ip))

    def test_different_ips_independent(self):
        """Two IPs don't interfere with each other's buckets."""
        from secure_tunnel.anti_probing import check_rate
        from secure_tunnel.config import RATE_LIMIT_PER_MIN
        ip_a = "10.1.1.1"
        ip_b = "10.2.2.2"
        for _ in range(RATE_LIMIT_PER_MIN):
            check_rate(ip_a)  # exhaust ip_a
        # ip_a is now blocked
        self.assertFalse(check_rate(ip_a))
        # ip_b must still be allowed
        self.assertTrue(check_rate(ip_b))


if __name__ == "__main__":
    unittest.main()
