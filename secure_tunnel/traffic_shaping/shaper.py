"""
ML-inspired Traffic Shaper.

Wraps any channel (TlsInTlsChannel / QuicChannel) and reshapes outgoing
traffic to statistically match a chosen TrafficProfile.

Techniques applied:
  1. Packet size normalization  — pads every frame to a size drawn from
                                  the profile's bimodal distribution
  2. Burst-based send scheduling — buffers frames and releases them in
                                   bursts that match the profile's burst model
  3. Inter-packet delay injection — adds log-normal delays between sends
  4. Cover traffic (dummy frames) — fills gaps with profile-sized noise
                                    frames so idle periods disappear

Result: an observer sees a packet-size histogram and inter-arrival time
distribution that is statistically indistinguishable from the target app.

Usage:
    channel = await tls_in_tls_connect(...).__aenter__()
    shaped  = ShapedChannel(channel, HTTPSBrowsingProfile)
    await shaped.start()

    await shaped.send(b"real data")   # same API as raw channel
    data = await shaped.recv()
    await shaped.stop()
"""
import asyncio
import os
import struct
from typing import Optional

from secure_tunnel.traffic_shaping.profiles import TrafficProfile, HTTPSBrowsingProfile


# Frame type tag embedded in cover-traffic frames so the receiver can discard them
_TAG_REAL  = b'\x01'
_TAG_COVER = b'\x00'
_TAG_LEN   = 1


class ShapedChannel:
    """
    Wraps an inner channel and applies traffic shaping on the send path.
    The recv path is transparent — shaping is only applied to outgoing traffic.

    Wire format of each shaped frame sent over the inner channel:
      [1B tag: REAL=0x01 / COVER=0x00][2B real_payload_len][payload][random pad]

    The total frame size is drawn from profile.sample_packet_size() so that
    every frame looks the same size-wise as a packet from the target app.
    """

    def __init__(self, channel, profile: TrafficProfile = HTTPSBrowsingProfile):
        self._ch = channel
        self._profile = profile
        self._send_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._burst_task: Optional[asyncio.Task] = None
        self._cover_task: Optional[asyncio.Task] = None
        self._running = False

    # -----------------------------------------------------------------------
    # Public API (same as TlsInTlsChannel / QuicChannel)
    # -----------------------------------------------------------------------

    async def start(self) -> None:
        """Start background shaping tasks. Call once after connecting."""
        self._running = True
        self._burst_task = asyncio.ensure_future(self._burst_pump())
        self._cover_task = asyncio.ensure_future(self._cover_pump())

    async def stop(self) -> None:
        self._running = False
        for task in (self._burst_task, self._cover_task):
            if task:
                task.cancel()

    async def send(self, data: bytes) -> None:
        """Enqueue real data for shaped delivery."""
        await self._send_queue.put(data)

    async def recv(self) -> bytes:
        """Receive and strip shaping wrapper. Discards cover frames transparently."""
        while True:
            raw = await self._ch.recv()
            tag = raw[:_TAG_LEN]
            if tag == _TAG_COVER:
                continue                   # silently drop cover traffic
            # Real frame: [tag 1B][real_len 2B][payload][pad]
            real_len = int.from_bytes(raw[_TAG_LEN:_TAG_LEN + 2], "big")
            return raw[_TAG_LEN + 2: _TAG_LEN + 2 + real_len]

    def __aiter__(self):
        return self

    async def __anext__(self) -> bytes:
        try:
            return await self.recv()
        except ConnectionError:
            raise StopAsyncIteration

    # -----------------------------------------------------------------------
    # Internal: burst pump — shaped delivery of real frames
    # -----------------------------------------------------------------------

    async def _burst_pump(self) -> None:
        """
        Reads from send_queue in bursts.
        Each burst sends N packets at profile inter-packet delays,
        then pauses for profile burst_pause before the next burst.
        """
        while self._running:
            burst_size = self._profile.sample_burst_size()
            sent = 0

            while sent < burst_size:
                try:
                    data = self._send_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break

                shaped = self._shape_real(data)
                try:
                    await self._ch.send(shaped)
                except Exception:
                    return

                sent += 1
                if sent < burst_size:
                    delay = self._profile.sample_delay()
                    await asyncio.sleep(delay)

            # Pause between bursts
            pause = self._profile.sample_burst_pause()
            await asyncio.sleep(pause)

    # -----------------------------------------------------------------------
    # Internal: cover pump — fills silence with dummy frames
    # -----------------------------------------------------------------------

    async def _cover_pump(self) -> None:
        """
        Continuously sends cover (dummy) frames when the send queue is idle.
        This eliminates silent periods that would distinguish a tunnel from
        a real streaming/browsing session.
        """
        while self._running:
            # Only send cover if queue has been idle for a moment
            await asyncio.sleep(self._profile.sample_delay())
            if self._send_queue.empty():
                cover = self._shape_cover()
                try:
                    await self._ch.send(cover)
                except Exception:
                    return

    # -----------------------------------------------------------------------
    # Frame construction
    # -----------------------------------------------------------------------

    def _shape_real(self, data: bytes) -> bytes:
        """
        Wrap real payload:
          [0x01][2B real_len][data][random padding to profile size]
        """
        real_len = len(data)
        target_size = self._profile.sample_packet_size()
        # Minimum: tag + 2B len + actual data
        min_size = _TAG_LEN + 2 + real_len
        target_size = max(target_size, min_size)
        pad_len = target_size - min_size
        return _TAG_REAL + real_len.to_bytes(2, "big") + data + os.urandom(pad_len)

    def _shape_cover(self) -> bytes:
        """
        Cover frame — looks identical in size to a real frame but carries no data.
          [0x00][random bytes to profile size]
        """
        target_size = self._profile.sample_packet_size()
        payload_size = max(1, target_size - _TAG_LEN)
        return _TAG_COVER + os.urandom(payload_size)
