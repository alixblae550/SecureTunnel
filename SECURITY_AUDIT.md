# SecureTunnel Security Audit — v4.4.0

**Audit team:** Principal Engineer · Staff Security Engineer · Network Protocol Engineer · SRE · Performance Engineer · Reverse Engineer · Adversarial Tester  
**Audit date:** 2026-04-04  
**Scope:** Full codebase review — architecture, cryptography, protocol, traffic analysis, anti-DPI, operational security

---

## 1. Architecture Overview

```
Browser/App
    │ SOCKS5 / HTTP CONNECT (127.0.0.1:1080 / :8080)
    ▼
Relay (tunnel_relay.py)  ──K1 (X25519+ML-KEM)──► Entry (entry_node.py)
                                                      │
                                               K2 (X25519+ML-KEM)
                                                      │
                                               Middle (node1.py)
                                                      │
                                               K3 (X25519+ML-KEM)
                                                      │
                                               Exit (exit_node.py)
                                                      │
                                               DoH resolver
                                                      │
                                               Internet
```

Each hop is an independent TLS-in-TLS channel with its own hybrid key exchange. The relay derives K1, K2, K3 independently via Tor-style EXTEND commands. No single node can read both source and destination.

---

## 2. Findings Summary

| ID | Severity | Title | Status |
|----|----------|-------|--------|
| F-01 | CRITICAL | Hardcoded AUTH_SECRET default | **FIXED v4.3.0** |
| F-02 | HIGH | HTTP proxy port mismatch (1081 vs 8080) | **FIXED v4.3.0** |
| F-03 | HIGH | Privacy leak: host:port logged in plaintext | **FIXED v4.3.0** |
| F-04 | MEDIUM | ChaCha20-Poly1305 nonce reuse risk | **FIXED v4.3.0** |
| F-05 | MEDIUM | Sequence number replay protection not integrated | **FIXED v4.4.0** |
| F-06 | MEDIUM | Pool size unbounded — resource exhaustion possible | **FIXED v4.4.0** |
| F-07 | MEDIUM | UDP relay: unbounded concurrent task count | **FIXED v4.4.0** |
| F-08 | LOW | onion_client.py / key_exchange.py were dead code | **FIXED v4.3.0** |
| F-09 | INFO | ML-KEM requires OpenSSL 3.5; falls back silently | Accepted — logged |
| F-10 | INFO | ECH not yet available in Python ssl/OpenSSL bindings | Deferred — documented |

---

## 3. Detailed Findings

### F-01 — CRITICAL: Hardcoded AUTH_SECRET

**File:** `secure_tunnel/config.py`

**Description:** The original code used a hardcoded string `"securetunnel-default-secret-CHANGE-ME"` as the AUTH_SECRET when the environment variable was not set. Any two installations with the same binary would share the same secret, allowing an adversary who obtained the binary to authenticate to all nodes.

**Fix:** The config module now:
- In **local mode** (all nodes on 127.0.0.1): auto-generates a cryptographically random 32-byte hex secret on first run and persists it to `auth_secret.key` (gitignored).
- In **production mode** (any remote node): calls `sys.exit(1)` with a clear error message if `AUTH_SECRET` is not set.

```python
POOL_SIZE: int = max(1, min(100, int(os.environ.get("POOL_SIZE", "12"))))
```

---

### F-02 — HIGH: HTTP Proxy Port Mismatch

**Files:** `secure_tunnel/http_proxy.py`, `launcher.py`

**Description:** `http_proxy.py` hardcoded port 1081 while the launcher UI showed 8080 as the HTTP proxy port. Users were configuring their browsers for 8080 but no proxy was listening there.

**Fix:** `http_proxy.py` now reads `HTTP_PORT` env var (default 8080). Launcher's `PROXY_ADDR` and kill-switch loop also corrected to 8080.

---

### F-03 — HIGH: Privacy Leak in Logs

**Files:** `secure_tunnel/socks5_proxy.py`, `secure_tunnel/exit_node.py`

**Description:** Multiple `print()` calls logged real destination host:port pairs and client peer IPs to stdout. In a forensic scenario, these log lines would expose browsing destinations.

**Fix:** All privacy-sensitive prints replaced with `log_event()` which logs only metadata (bytes, event type, session ID). Destination addresses never appear in logs.

---

### F-04 — MEDIUM: ChaCha20-Poly1305 Nonce Reuse Risk

**File:** `secure_tunnel/crypto.py`

**Description:** The original implementation used ChaCha20-Poly1305 with random 96-bit nonces. With a birthday bound of ~2^48 frames, nonce collision probability reaches 0.1% after ~2^43 frames — a real risk for long-lived high-throughput sessions. A nonce collision in ChaCha20-Poly1305 catastrophically exposes the keystream.

**Fix:** Switched to **AES-256-GCM-SIV** (nonce-misuse-resistant). Even if a nonce is accidentally reused, SIV construction only reveals that identical plaintext was sent twice — the session key and all other plaintexts remain secure. This is a strictly stronger guarantee.

```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
_NONCE_LEN = 12
```

Note: XChaCha20-Poly1305 (192-bit nonce, no birthday risk) was the first choice but is not exposed in `cryptography` 46.x. AES-GCM-SIV is equivalent security with a practical nonce-misuse-resistance bonus.

---

### F-05 — MEDIUM: Replay Protection Not Integrated

**Files:** `secure_tunnel/protocol.py`, `secure_tunnel/tunnel_relay.py`, `secure_tunnel/entry_node.py`, `secure_tunnel/node1.py`, `secure_tunnel/exit_node.py`

**Description:** The `ReplayFilter` class existed in `protocol.py` but was never called anywhere. All frames used `seq_no=0`. An adversary who could record and replay a valid AES-GCM-SIV ciphertext (same nonce+tag) would have it accepted as legitimate by the receiving node.

**Fix (v4.4.0):**
1. `tunnel_relay.py` — `_make_cmd_helpers` now maintains a per-connection outbound `_seq_out` counter and an inbound `ReplayFilter`. Outgoing frames carry incrementing seq_no; incoming frames are validated.
2. `exit_node.py` — Added outbound seq counter and inbound `ReplayFilter` in the per-connection `_send_cmd`/`_parse_cmd` closures.
3. `entry_node.py` — Added `relay_replay = ReplayFilter()` validated on every inbound relay frame (both EXTEND phase and forward loop).
4. `node1.py` — Added `entry_replay = ReplayFilter()` validated on every inbound entry frame.

---

### F-06 — MEDIUM: Unbounded Pool Size

**File:** `secure_tunnel/config.py`

**Description:** `POOL_SIZE = int(os.environ.get("POOL_SIZE", "12"))` with no upper bound. Setting `POOL_SIZE=100000` would exhaust file descriptors and memory.

**Fix:**
```python
POOL_SIZE: int = max(1, min(100, int(os.environ.get("POOL_SIZE", "12"))))
POOL_SEMAPHORE: int = max(1, min(50, int(os.environ.get("POOL_SEMAPHORE", "10"))))
```

---

### F-07 — MEDIUM: UDP Relay Task Flood

**File:** `secure_tunnel/socks5_proxy.py`

**Description:** `_UDPRelay.datagram_received()` called `asyncio.ensure_future()` unconditionally for every incoming datagram. A UDP flood of 10,000 datagrams/s would spawn 10,000 concurrent coroutines, exhausting memory and event loop capacity.

**Fix:** Added `_active_tasks` counter capped at `_MAX_UDP_TASKS = 64`. Excess datagrams are silently dropped (logged as `udp_flood_drop`).

```python
def datagram_received(self, data, addr):
    if self._active_tasks >= _MAX_UDP_TASKS:
        log_event("socks5", 0, 0, 0, "udp_flood_drop")
        return
    self._active_tasks += 1
    asyncio.ensure_future(self._relay(data, addr))
```

---

### F-08 — LOW: Dead Code (onion_client.py, key_exchange.py)

**Files:** `secure_tunnel/onion_client.py`, `secure_tunnel/key_exchange.py`

**Description:** Both files existed in the codebase but were never called. `key_exchange.py` contained a `PQKeyExchangeStub` with XOR "encryption" masquerading as post-quantum crypto.

**Fix (v4.3.0):** Both files were rewritten and connected to the live circuit:
- `key_exchange.py` — Real `HybridKeyExchange` using `derive_session_key` + ML-KEM-768
- `onion_client.py` — True 3-hop onion circuit via `EXTEND_K2` / `EXTEND_K3` commands

---

## 4. Cryptographic Audit

### Key Exchange

| Layer | Algorithm | Security |
|-------|-----------|---------|
| Classical | X25519 ECDH | 128-bit equivalent |
| Post-quantum | ML-KEM-768 | 192-bit post-quantum |
| Combination | HKDF-SHA256(x25519_ss \|\| mlkem_ss) | Breakable only if BOTH fail |
| Fallback | X25519-only (OpenSSL < 3.5) | 128-bit classical |

**Assessment:** Hybrid construction is correct. Concatenation before HKDF ensures the combined key is secure as long as either component is unbroken.

### Payload Encryption

| Property | Value |
|----------|-------|
| Algorithm | AES-256-GCM-SIV |
| Nonce | 96-bit random per frame |
| Key size | 256 bits |
| Nonce-misuse resistance | Yes (SIV) |
| Authentication | GHASH (96-bit tag) |

**Assessment:** Nonce-misuse-resistant AEAD is a strong choice for random nonces. The SIV guarantee prevents catastrophic failure on accidental nonce reuse. Authentication tag size (128 bits after GCM) is standard.

### Replay Protection

- `ReplayFilter` uses a 64-frame sliding window with 32-bit wraparound-safe modular arithmetic.
- Outbound counters in relay and exit nodes are now incremented per-frame.
- Entry and middle nodes validate inbound seq_no against per-connection `ReplayFilter` instances.

**Residual gap:** The middle-to-exit direction uses random `secrets.randbits(32)` seq_no (forwarded from entry). A targeted replay on this internal hop would require breaking the outer TLS-in-TLS channel — acceptable risk level.

---

## 5. Anti-DPI Analysis

### Traffic Fingerprint

| Property | Technique |
|----------|-----------|
| Outer TLS | Chrome-like fingerprint (via OpenSSL SNI pool) |
| SNI values | Windows Update, NVIDIA telemetry, Google CDN, DigiCert OCSP |
| Packet sizes | 12-bucket padding (256B–16384B) normalizes size histogram |
| Timing | Sinusoidal cover traffic (mimics 14:00 activity peak, ±15% jitter) |
| Idle periods | Cover frames injected so "silence ≠ no activity" |
| Anti-probing | HMAC challenge inside inner TLS + rate limiting + decoy forward |

### Remaining Fingerprints

1. **TLS-in-TLS depth** — Two nested TLS sessions are unusual. Deep packet inspection by a state-level adversary with hardware offload could detect the inner TLS ClientHello inside the outer TLS data.
   - Mitigation: inner TLS cert should be a self-signed cert with a plausible CN matching the outer SNI.
   - Future: ECH (Encrypted Client Hello) would solve this once Python `ssl` module exposes it.

2. **Fixed connection pre-warming** — The POOL_SIZE=12 pre-warmed connections create a distinctive burst of 12 simultaneous TLS handshakes on startup.
   - Mitigation: stagger pool warming (already done with batch=4 fills).

3. **Cover traffic rhythm** — Even with sinusoidal variation, a sophisticated ML classifier trained on the sinusoidal pattern could potentially identify the tunnel.
   - Mitigation: ±15% random jitter breaks regularity; acceptable for current threat model.

---

## 6. Red Team Scenarios

### Scenario A: Passive Traffic Analysis
**Threat:** Observer records all TLS traffic, applies ML classifier to packet sizes and timing.  
**Resistance:** Bucket padding normalizes sizes to 12 discrete values; sinusoidal cover traffic with jitter prevents timing fingerprinting.  
**Rating:** Moderate-High resistance.

### Scenario B: Active Probing
**Threat:** Adversary connects to node ports with a standard TLS client to fingerprint the service.  
**Resistance:** Outer TLS looks like a web server; nodes forward connections to real CDN/update servers matching the SNI. Without the AUTH_SECRET, the adversary cannot distinguish this from a normal HTTPS server.  
**Rating:** High resistance.

### Scenario C: Replay Attack
**Threat:** Adversary records encrypted tunnel frames and replays them to inject commands.  
**Resistance (post-fix):** AES-GCM-SIV authentication prevents modification. `ReplayFilter` with 64-frame window rejects duplicates. Incrementing `seq_no` prevents same-session replays.  
**Rating:** High resistance (after v4.4.0 fixes).

### Scenario D: Node Compromise
**Threat:** Adversary fully compromises one node.  
**Resistance:** Entry knows relay IP + K1. Middle knows only K2. Exit knows only destination. No single node can link source to destination. K1/K2/K3 are independently derived by the relay client.  
**Rating:** High resistance (proper onion routing).

### Scenario E: Quantum Adversary
**Threat:** Future quantum computer breaks X25519.  
**Resistance (when ML-KEM available):** ML-KEM-768 shared secret is combined with X25519 via HKDF. Quantum computer can break X25519 but not ML-KEM. Session key remains secure.  
**Resistance (when ML-KEM unavailable):** Falls back to X25519 only — vulnerable to quantum adversary with CRQC.  
**Rating:** High (with ML-KEM) / Low (without).

---

## 7. Performance Notes

- **Pool pre-warming:** 12 connections × 3 TLS handshakes per connection = 36 TLS handshakes on startup. Batched to 4 concurrent.
- **Cover traffic:** Sinusoidal model adds 3–60s intervals of background traffic proportional to time-of-day.
- **Jitter:** 5–40ms per frame adds latency. Acceptable for proxy use, noticeable for latency-sensitive apps (gaming, VoIP).
- **ReplayFilter:** `set` membership check is O(1). Window eviction is O(window_size). No performance concern.
- **AES-GCM-SIV vs ChaCha20:** On hardware with AES-NI (any modern x86), AES-GCM-SIV is faster than ChaCha20. On ARM without crypto extensions, ChaCha20 would be faster — not a concern for desktop/server deployment.

---

## 8. Test Coverage

| Test file | Tests | What is covered |
|-----------|-------|-----------------|
| `tests/test_crypto.py` | 8 | HKDF derivation, ML-KEM roundtrip |
| `tests/test_framing.py` | 8 | Bucket padding, parse/build roundtrip, wrong key |
| `tests/test_auth.py` | 10 | HMAC challenge/response, rate limiting |
| `tests/test_key_exchange.py` | 20 | X25519, ML-KEM, HybridKeyExchange, ReplayFilter |
| **Total** | **46** | Core crypto + protocol + auth + rate-limiting |

4 tests are skipped when ML-KEM is unavailable (requires OpenSSL 3.5).

Run all tests:
```bash
python -m pytest tests/ -v
```

---

## 9. Operational Security Checklist

Before deploying to VPS nodes, verify:

- [ ] `AUTH_SECRET` env var set identically on ALL nodes AND the client machine
- [ ] `auth_secret.key` is in `.gitignore` and never committed
- [ ] `cert.pem` / `key.pem` are node-specific, not shared
- [ ] `secure_tunnel_keys/*.key` are gitignored
- [ ] Firewall allows only expected port(s) per node
- [ ] Nodes are in different jurisdictions / autonomous systems
- [ ] POOL_SIZE tuned for expected load (default 12 is suitable for 1–10 concurrent users)
- [ ] COVER_SNI matches outer TLS SNI for plausible traffic blending

---

## 10. Fix Roadmap (Future)

| Priority | Item |
|----------|------|
| HIGH | ECH (Encrypted Client Hello) — when Python ssl exposes OpenSSL 3.2+ ECH API |
| MEDIUM | Middle→exit seq_no tracking (replace `secrets.randbits(32)` with per-connection counter) |
| MEDIUM | XChaCha20-Poly1305 (192-bit nonce) — when `cryptography` package exposes it |
| LOW | Tor-style circuit teardown handshake (clean DESTROY cell) |
| LOW | Multiple circuits per session for load balancing |
| INFO | Consider obfs4 or Shadowsocks obfuscation layer for highly censored environments |
