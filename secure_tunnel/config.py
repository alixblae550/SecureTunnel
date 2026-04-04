"""
SecureTunnel — circuit configuration.

3-node topology: Entry → Middle → Exit

For VPS deployment set environment variables (no code edits needed):
    ENTRY_HOST=1.2.3.4   ENTRY_PORT=443
    MIDDLE_HOST=5.6.7.8  MIDDLE_PORT=443
    EXIT_HOST=9.10.11.12 EXIT_PORT=443
    AUTH_SECRET=your-long-random-secret-here
    COVER_SNI=update.googleapis.com

All nodes default to localhost for local / dev / test runs.
"""
import os

# ── Node addresses ────────────────────────────────────────────────────────────

NODES = {
    "entry": {
        "name": "entry",
        "host": os.environ.get("ENTRY_HOST", "127.0.0.1"),
        "port": int(os.environ.get("ENTRY_PORT", "8765")),
    },
    "middle": {
        "name": "middle",
        "host": os.environ.get("MIDDLE_HOST", "127.0.0.1"),
        "port": int(os.environ.get("MIDDLE_PORT", "8766")),
    },
    "exit": {
        "name": "exit",
        "host": os.environ.get("EXIT_HOST", "127.0.0.1"),
        "port": int(os.environ.get("EXIT_PORT", "8767")),
    },
}

# Ordered list: relay connects to ROUTE[0], ROUTE[0] forwards to ROUTE[1], etc.
ROUTE = [NODES["entry"], NODES["middle"], NODES["exit"]]

# ── Anti-probing ──────────────────────────────────────────────────────────────
# Shared secret for HMAC challenge-response inside TLS.
# Change before deployment. Set AUTH_SECRET env var on each VPS.
# Must be identical on all nodes and all clients.
_auth_secret_raw = os.environ.get("AUTH_SECRET", "securetunnel-default-secret-CHANGE-ME")
if _auth_secret_raw == "securetunnel-default-secret-CHANGE-ME":
    print("[config] Running with default AUTH_SECRET (local mode)", flush=True)
AUTH_SECRET: bytes = _auth_secret_raw.encode()

# Connections per IP per minute before silent drop
RATE_LIMIT_PER_MIN: int = int(os.environ.get("RATE_LIMIT", "30"))

# Seconds to wait for inner-TLS ClientHello before sending decoy
PROBE_TIMEOUT: float = float(os.environ.get("PROBE_TIMEOUT", "4.0"))

# ── Circuit rotation ──────────────────────────────────────────────────────────
# Rotate (replace all tunnel connections) every N seconds OR M requests.
CIRCUIT_TTL_SECONDS:   int = int(os.environ.get("CIRCUIT_TTL",  "300"))   # 5 min
CIRCUIT_MAX_REQUESTS:  int = int(os.environ.get("CIRCUIT_REQS", "500"))

# ── Traffic shaping — jitter ──────────────────────────────────────────────────
# Random delay injected before each DATA frame (milliseconds).
JITTER_MIN_MS: float = float(os.environ.get("JITTER_MIN", "5"))
JITTER_MAX_MS: float = float(os.environ.get("JITTER_MAX", "40"))

# ── Traffic shaping — cover traffic ──────────────────────────────────────────
# Interval (seconds) between cover frames when the tunnel is idle.
COVER_MIN_INTERVAL: float = float(os.environ.get("COVER_MIN", "2.0"))
COVER_MAX_INTERVAL: float = float(os.environ.get("COVER_MAX", "9.0"))

# ── Fixed-size padding buckets (bytes) ───────────────────────────────────────
# 12 sizes for a smoother, more natural-looking packet-size histogram.
# Range: 256 B (small ACKs/heartbeats) → 16384 B (large data transfers).
PADDING_BUCKETS: list[int] = [
    256, 512, 768, 1024, 1536, 2048,
    3072, 4096, 6144, 8192, 12288, 16384,
]

# ── TLS / cover SNI pool ──────────────────────────────────────────────────────
# Per-connection random SNI is drawn from this pool.
# Domains are chosen to blend into update/telemetry background traffic that
# ISPs will not dare block:
#   • Windows telemetry / update CDN
#   • NVIDIA telemetry (ubiquitous on gaming PCs)
#   • Google update infrastructure
#   • Cloudflare OCSP / CT logs (permanent background noise)
SNI_POOL: list[str] = [
    "settings-win.data.microsoft.com",    # Windows telemetry
    "v10.events.data.microsoft.com",      # Windows diagnostics
    "ds.download.windowsupdate.com",      # Windows Update CDN
    "updates.microsoft.com",              # Windows Update
    "telemetry.nvidia.com",               # NVIDIA telemetry
    "update.googleapis.com",              # Google updater
    "clients1.google.com",                # Google services
    "ocsp.digicert.com",                  # DigiCert OCSP (constant background)
]

# Active SNI for this process — set via env to pin a specific value on VPS;
# leave empty to draw randomly from SNI_POOL on each connection.
COVER_SNI: str = os.environ.get("COVER_SNI", "")

# Domain fronting: if FRONT_HOST is set, connect TCP to FRONT_HOST but send
# COVER_SNI in ClientHello.  Leave empty for direct connection.
FRONT_HOST: str = os.environ.get("FRONT_HOST", "")

# ── ECH (Encrypted Client Hello) ─────────────────────────────────────────────
# ECH fully encrypts the SNI in the ClientHello so DPI cannot read it.
# Status: Python ssl / OpenSSL bindings do NOT expose ECH API yet (requires
# OpenSSL 3.2+ with ECH patch + Python ssl rebuild).
# TODO: switch inner TLS to a library with ECH support when available.
# Reference: https://datatracker.ietf.org/doc/draft-ietf-tls-esni/

# ── Legacy dummy-traffic config (used by ShapedChannel) ──────────────────────
DUMMY_CONFIG = {
    "ratio":        0.4,
    "min_interval": 0.2,
    "max_interval": 1.5,
    "min_payload":  16,
    "max_payload":  128,
}
