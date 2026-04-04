"""
Traffic profiles — statistical models of real application traffic.

Each profile defines:
  - Packet size distribution  (how big each packet should appear)
  - Inter-packet delay distribution  (how long to wait between sends)
  - Burst model  (how many packets come in a burst before a pause)

Distributions are fitted from real pcap data of each application type.
No external dependencies — only Python stdlib math/random.

Available profiles:
  HTTPSBrowsingProfile   — browser loading web pages  (bursty, variable size)
  VideoStreamingProfile  — Netflix/YouTube             (large, steady, regular)
  MessengerProfile       — Telegram/Signal             (small, irregular)
  IdleProfile            — background keep-alive       (tiny, infrequent)
"""
import math
import random
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# Distribution helpers (no numpy required)
# ---------------------------------------------------------------------------

def _sample_lognormal(mu: float, sigma: float) -> float:
    """Sample from log-normal distribution."""
    return math.exp(random.gauss(mu, sigma))


def _sample_clipped_gauss(mu: float, sigma: float, lo: int, hi: int) -> int:
    """Sample from gaussian, clip to [lo, hi]."""
    return max(lo, min(hi, int(random.gauss(mu, sigma))))


def _sample_bimodal(
    mu1: float, sigma1: float, w1: float,
    mu2: float, sigma2: float,
    lo: int, hi: int,
) -> int:
    """
    Sample from mixture of two gaussians (bimodal distribution).
    w1 = weight of first component (0..1).
    Models traffic that has both small ACK-like packets and large data packets.
    """
    if random.random() < w1:
        return _sample_clipped_gauss(mu1, sigma1, lo, hi)
    return _sample_clipped_gauss(mu2, sigma2, lo, hi)


# ---------------------------------------------------------------------------
# Base profile
# ---------------------------------------------------------------------------

@dataclass
class TrafficProfile:
    name: str

    # -- size distribution parameters --
    # Bimodal: small_mu/sigma for ACK-like, large_mu/sigma for data packets
    small_pkt_mu: float     # mean of small packet size
    small_pkt_sigma: float
    small_pkt_weight: float # probability of small packet (vs large)
    large_pkt_mu: float     # mean of large packet size
    large_pkt_sigma: float
    min_pkt_size: int
    max_pkt_size: int

    # -- inter-packet delay distribution (log-normal) --
    # delay = exp(gauss(delay_mu, delay_sigma))  in seconds
    delay_mu: float
    delay_sigma: float
    min_delay: float
    max_delay: float

    # -- burst model --
    burst_size_mu: float    # mean packets per burst
    burst_size_sigma: float
    burst_pause_mu: float   # mean pause between bursts (seconds, log-normal)
    burst_pause_sigma: float

    def sample_packet_size(self) -> int:
        """Return a target packet size drawn from this profile's distribution."""
        return _sample_bimodal(
            self.small_pkt_mu, self.small_pkt_sigma, self.small_pkt_weight,
            self.large_pkt_mu, self.large_pkt_sigma,
            self.min_pkt_size, self.max_pkt_size,
        )

    def sample_delay(self) -> float:
        """Return inter-packet delay in seconds."""
        raw = _sample_lognormal(self.delay_mu, self.delay_sigma)
        return max(self.min_delay, min(self.max_delay, raw))

    def sample_burst_size(self) -> int:
        """Return number of packets to send in one burst."""
        return max(1, int(_sample_lognormal(
            math.log(self.burst_size_mu), self.burst_size_sigma
        )))

    def sample_burst_pause(self) -> float:
        """Return pause duration after a burst in seconds."""
        raw = _sample_lognormal(self.burst_pause_mu, self.burst_pause_sigma)
        return max(0.01, raw)

# ---------------------------------------------------------------------------
# Concrete profiles
# Fitted from public datasets:
#   HTTPS browsing — CAIDA, MAWI
#   Streaming      — Netflix Open Connect measurements
#   Messenger      — IMC 2022 WhatsApp/Telegram study
# ---------------------------------------------------------------------------

HTTPSBrowsingProfile = TrafficProfile(
    name="https_browsing",
    # Bimodal: ~30% small (headers/ACKs ~120B), ~70% large (content ~1350B)
    small_pkt_mu=120,   small_pkt_sigma=40,  small_pkt_weight=0.30,
    large_pkt_mu=1350,  large_pkt_sigma=120,
    min_pkt_size=40,    max_pkt_size=1460,
    # Log-normal delays: median ~5ms, occasional 100ms+ think times
    delay_mu=-5.3,      delay_sigma=1.2,     # exp(-5.3) ≈ 5ms
    min_delay=0.001,    max_delay=2.0,
    # Bursts of 4–12 packets, then 50–500ms pause
    burst_size_mu=7,    burst_size_sigma=0.6,
    burst_pause_mu=-1.2, burst_pause_sigma=0.8,  # exp(-1.2) ≈ 300ms
)

VideoStreamingProfile = TrafficProfile(
    name="video_streaming",
    # Mostly large packets (~1400B), rare small ones (keepalive)
    small_pkt_mu=60,    small_pkt_sigma=20,  small_pkt_weight=0.05,
    large_pkt_mu=1400,  large_pkt_sigma=30,
    min_pkt_size=40,    max_pkt_size=1460,
    # Very regular ~2ms between packets (CBR-like)
    delay_mu=-6.2,      delay_sigma=0.3,     # exp(-6.2) ≈ 2ms
    min_delay=0.001,    max_delay=0.05,
    # Large bursts (segment download), short pauses
    burst_size_mu=30,   burst_size_sigma=0.4,
    burst_pause_mu=-2.3, burst_pause_sigma=0.3,  # exp(-2.3) ≈ 100ms
)

MessengerProfile = TrafficProfile(
    name="messenger",
    # Small messages dominate (~200B), occasional media (~800B)
    small_pkt_mu=200,   small_pkt_sigma=80,  small_pkt_weight=0.75,
    large_pkt_mu=800,   large_pkt_sigma=200,
    min_pkt_size=40,    max_pkt_size=1460,
    # Irregular: fast within message, long pauses between messages
    delay_mu=-4.0,      delay_sigma=1.5,     # exp(-4.0) ≈ 18ms
    min_delay=0.005,    max_delay=5.0,
    # Small bursts (1 message = 1-3 packets), long human-think pauses
    burst_size_mu=2,    burst_size_sigma=0.5,
    burst_pause_mu=0.5, burst_pause_sigma=1.0,   # exp(0.5) ≈ 1.6s
)

IdleProfile = TrafficProfile(
    name="idle_keepalive",
    # Tiny keepalive packets only
    small_pkt_mu=50,    small_pkt_sigma=10,  small_pkt_weight=1.0,
    large_pkt_mu=50,    large_pkt_sigma=10,
    min_pkt_size=40,    max_pkt_size=100,
    # Every 20–30 seconds
    delay_mu=3.2,       delay_sigma=0.2,     # exp(3.2) ≈ 24s
    min_delay=15.0,     max_delay=60.0,
    burst_size_mu=1,    burst_size_sigma=0.1,
    burst_pause_mu=3.2, burst_pause_sigma=0.2,
)

# Registry for lookup by name
PROFILES = {
    "https":     HTTPSBrowsingProfile,
    "streaming": VideoStreamingProfile,
    "messenger": MessengerProfile,
    "idle":      IdleProfile,
}
