"""
DNS over HTTPS (DoH) resolver — fully async, no thread pool.

Improvements over original:
  - Pure asyncio SSL streams instead of blocking urllib in executor
  - In-flight deduplication: N concurrent resolves for the same host share one query
  - ssl context created at module level (before event loop) — safe from Python 3.14
    GeneratorExit bug that affects ssl.create_default_context() inside coroutines
"""
import asyncio
import json
import re
import ssl
import time

_DOH_PROVIDERS = [
    ("cloudflare-dns.com", "/dns-query"),
    ("dns.google",         "/resolve"),
]

# Module-level creation — safe (no running event loop, no cancellation risk)
_ssl_ctx = ssl.create_default_context()

# Cache: hostname -> (ip, expires_at)
_cache: dict[str, tuple[str, float]] = {}
_DEFAULT_TTL = 300.0  # 5 minutes

# In-flight futures: hostname -> Future[ip]
# Concurrent resolves for the same host wait on the same future instead of
# each making a separate DoH query.
_inflight: dict[str, "asyncio.Future[str]"] = {}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


async def _query_doh(hostname: str) -> tuple[str, float]:
    """Async DoH query using asyncio SSL streams — zero thread overhead."""
    for host, path in _DOH_PROVIDERS:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, 443, ssl=_ssl_ctx),
                timeout=5.0,
            )
            try:
                request = (
                    f"GET {path}?name={hostname}&type=A HTTP/1.1\r\n"
                    f"Host: {host}\r\n"
                    f"Accept: application/dns-json\r\n"
                    f"Connection: close\r\n\r\n"
                )
                writer.write(request.encode())
                await writer.drain()

                # Read until EOF (response is small, usually one packet)
                raw = b""
                while True:
                    chunk = await asyncio.wait_for(reader.read(8192), timeout=5.0)
                    if not chunk:
                        break
                    raw += chunk
                    if len(raw) > 65536:
                        break
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

            # Strip HTTP headers
            sep = raw.find(b"\r\n\r\n")
            if sep == -1:
                continue
            body = raw[sep + 4:]
            data = json.loads(body)
            answers = [r for r in data.get("Answer", []) if r.get("type") == 1]
            if answers:
                ip = answers[0]["data"]
                ttl = float(answers[0].get("TTL", _DEFAULT_TTL))
                return ip, max(ttl, 10.0)
        except Exception:
            continue
    raise OSError(f"DoH resolution failed for {hostname!r}")


async def resolve(hostname: str) -> str:
    """
    Async DoH resolution with TTL cache and in-flight deduplication.
    Returns IP address string, or raises OSError on failure.
    Skips DoH if hostname is already an IP address.
    """
    if _IPV4_RE.match(hostname):
        return hostname
    if ":" in hostname:
        return hostname

    now = time.monotonic()
    cached = _cache.get(hostname)
    if cached and now < cached[1]:
        return cached[0]

    # Deduplicate: if another coroutine is already resolving this hostname, wait for it
    existing = _inflight.get(hostname)
    if existing is not None:
        return await asyncio.shield(existing)

    loop = asyncio.get_running_loop()
    fut: asyncio.Future = loop.create_future()
    _inflight[hostname] = fut
    try:
        ip, ttl = await _query_doh(hostname)
        _cache[hostname] = (ip, time.monotonic() + ttl)
        fut.set_result(ip)
        return ip
    except Exception as exc:
        if not fut.done():
            fut.set_exception(exc)
        raise
    finally:
        _inflight.pop(hostname, None)
