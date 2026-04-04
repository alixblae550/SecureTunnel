"""
SecureTunnel stress test — запускает все компоненты и нагружает прокси.

Что тестируется:
  1. Время холодного старта (от запуска до готовности всех компонентов)
  2. Одиночные HTTP CONNECT запросы через прокси (latency)
  3. N параллельных соединений одновременно (throughput / pool exhaustion)
  4. Выживаемость под 60 секунд непрерывной нагрузки
  5. Восстановление пула после исчерпания

Запуск:
  cd secure_tunnel
  python stress_test.py
"""
import asyncio
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).parent
PYTHON = sys.executable

HTTP_PROXY_HOST = "127.0.0.1"
HTTP_PROXY_PORT = 1081
SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 1080

# Target for testing — fast, reliable, returns small response
TEST_HOST = "example.com"
TEST_PORT = 80
TEST_REQUEST = b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def p(color, msg):
    print(f"{color}{msg}{RESET}", flush=True)


# ---------------------------------------------------------------------------
# Process management
# ---------------------------------------------------------------------------

procs: list[subprocess.Popen] = []

READY_SIGNALS = {
    "secure_tunnel.exit_node":    b"[exit] listening",
    "secure_tunnel.node1":        b"[node1] listening",
    "secure_tunnel.socks5_proxy": b"[relay] tunnel pool ready",
    "secure_tunnel.http_proxy":   b"[http_proxy] listening",
}


def launch(module: str) -> subprocess.Popen:
    import os
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    proc = subprocess.Popen(
        [PYTHON, "-u", "-m", module],
        cwd=str(BASE),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    procs.append(proc)
    return proc


def wait_ready(proc: subprocess.Popen, signal: bytes, timeout: float = 30.0) -> float:
    """Wait for signal in proc stdout. Returns seconds elapsed."""
    import select
    import threading

    t0 = time.monotonic()
    found = threading.Event()
    lines_seen: list[bytes] = []

    def _reader():
        for raw_line in proc.stdout:
            line = raw_line if isinstance(raw_line, bytes) else raw_line.encode()
            lines_seen.append(line)
            sys.stdout.buffer.write(b"  | " + line)
            sys.stdout.buffer.flush()
            if signal in line:
                found.set()
                # keep reading so stdout doesn't block
        found.set()  # EOF — unblock wait

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    if found.wait(timeout=timeout):
        # Check if signal was actually seen (not just EOF)
        elapsed = time.monotonic() - t0
        if any(signal in l for l in lines_seen):
            return elapsed
        raise TimeoutError(f"Process exited without printing {signal!r}")
    raise TimeoutError(f"Process did not print {signal!r} within {timeout}s")


def drain_stdout_bg(proc: subprocess.Popen):
    """Drain stdout in background thread so it doesn't block."""
    import threading
    def _drain():
        try:
            for _ in proc.stdout:
                pass
        except Exception:
            pass
    threading.Thread(target=_drain, daemon=True).start()


def stop_all():
    for p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    procs.clear()


# ---------------------------------------------------------------------------
# Connectivity helpers
# ---------------------------------------------------------------------------

async def http_connect(host: str, port: int, timeout: float = 30.0) -> float:
    """
    Open HTTP CONNECT tunnel through 127.0.0.1:1081.
    Returns round-trip time (seconds) from connect to first response byte.
    """
    t0 = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(HTTP_PROXY_HOST, HTTP_PROXY_PORT),
        timeout=timeout,
    )
    try:
        writer.write(f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
        await writer.drain()
        resp = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if b"200" not in resp:
            raise ConnectionError(f"Proxy returned: {resp[:80]}")
        # Send HTTP GET and read first byte of response to confirm end-to-end
        writer.write(TEST_REQUEST)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not data:
            raise ConnectionError("No data from target")
        return time.monotonic() - t0
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def socks5_connect(host: str, port: int, timeout: float = 10.0) -> float:
    """Direct SOCKS5 connection test. Returns RTT."""
    t0 = time.monotonic()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(SOCKS5_HOST, SOCKS5_PORT),
        timeout=timeout,
    )
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        r = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
        if r[1] != 0:
            raise ConnectionError("SOCKS5 auth rejected")
        host_b = host.encode()
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", port))
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
        if hdr[1] != 0:
            raise ConnectionError(f"SOCKS5 CONNECT failed: REP={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            await reader.readexactly(6)
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n + 2)
        elif atyp == 4:
            await reader.readexactly(18)
        writer.write(TEST_REQUEST)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        if not data:
            raise ConnectionError("No data from target")
        return time.monotonic() - t0
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

async def test_single_latency(n: int = 10) -> dict:
    """Sequential requests — pure latency without pool competition."""
    p(CYAN, f"\n[test 1] Sequential latency ({n} requests)…")
    times = []
    errors = 0
    for i in range(n):
        try:
            t = await http_connect(TEST_HOST, TEST_PORT)
            times.append(t)
            print(f"  #{i+1:02d}  {t*1000:.0f} ms", flush=True)
        except Exception as e:
            errors += 1
            print(f"  #{i+1:02d}  ERROR: {e}", flush=True)
    if times:
        avg = sum(times) / len(times)
        mn  = min(times)
        mx  = max(times)
        p(GREEN if errors == 0 else YELLOW,
          f"  avg={avg*1000:.0f}ms  min={mn*1000:.0f}ms  max={mx*1000:.0f}ms  errors={errors}/{n}")
    return {"avg": sum(times)/len(times) if times else 0, "errors": errors, "n": n}


async def test_concurrent(concurrency: int = 20) -> dict:
    """Fire N connections simultaneously — tests pool under load."""
    p(CYAN, f"\n[test 2] Concurrent connections ({concurrency} simultaneous)…")
    t0 = time.monotonic()

    async def _one(idx):
        try:
            t = await http_connect(TEST_HOST, TEST_PORT, timeout=35.0)
            return ("ok", t)
        except Exception as e:
            return ("err", str(e))

    results = await asyncio.gather(*[_one(i) for i in range(concurrency)])
    elapsed = time.monotonic() - t0

    ok    = [r[1] for r in results if r[0] == "ok"]
    errs  = [r[1] for r in results if r[0] == "err"]
    if ok:
        avg = sum(ok) / len(ok)
        p(GREEN if not errs else YELLOW,
          f"  ok={len(ok)}/{concurrency}  avg_rtt={avg*1000:.0f}ms  "
          f"wall={elapsed*1000:.0f}ms  errors={len(errs)}")
    else:
        p(RED, f"  ALL FAILED ({concurrency}/{concurrency})")
    for e in errs[:5]:
        print(f"    err: {e}", flush=True)
    return {"ok": len(ok), "errors": len(errs), "concurrency": concurrency}


async def test_sustained(duration: float = 30.0, rate: float = 3.0) -> dict:
    """
    Sustained load: send `rate` requests/sec for `duration` seconds.
    Tests pool refill under continuous pressure.
    """
    p(CYAN, f"\n[test 3] Sustained load ({rate:.0f} req/s for {duration:.0f}s)…")
    t0 = time.monotonic()
    ok = 0
    errors = 0
    total = 0
    interval = 1.0 / rate

    while time.monotonic() - t0 < duration:
        start = time.monotonic()
        try:
            await asyncio.wait_for(http_connect(TEST_HOST, TEST_PORT), timeout=15.0)
            ok += 1
        except Exception as e:
            errors += 1
            if errors <= 3:
                print(f"  err: {e}", flush=True)
        total += 1
        elapsed_req = time.monotonic() - start
        sleep = interval - elapsed_req
        if sleep > 0:
            await asyncio.sleep(sleep)
        if total % 10 == 0:
            print(f"  t={time.monotonic()-t0:.0f}s  ok={ok}  err={errors}", flush=True)

    p(GREEN if errors == 0 else YELLOW,
      f"  total={total}  ok={ok}  errors={errors}  "
      f"success_rate={ok/total*100:.1f}%")
    return {"total": total, "ok": ok, "errors": errors}


async def test_pool_exhaustion(pool_size: int = 12) -> dict:
    """
    Fire pool_size*2 requests at once — half should hit fresh connections.
    Checks that pool recovers after exhaustion.
    """
    p(CYAN, f"\n[test 4] Pool exhaustion ({pool_size*2} req, pool={pool_size})…")

    async def _one(idx):
        try:
            t = await http_connect(TEST_HOST, TEST_PORT, timeout=35.0)
            return ("ok", t)
        except Exception as e:
            return ("err", str(e))

    results = await asyncio.gather(*[_one(i) for i in range(pool_size * 2)])
    ok   = [r[1] for r in results if r[0] == "ok"]
    errs = [r[1] for r in results if r[0] == "err"]
    avg  = sum(ok) / len(ok) if ok else 0
    p(GREEN if len(ok) >= pool_size else YELLOW,
      f"  ok={len(ok)}/{pool_size*2}  avg_rtt={avg*1000:.0f}ms  errors={len(errs)}")

    p(CYAN, "  Waiting 5s for pool to refill…")
    await asyncio.sleep(5)
    p(CYAN, "  Re-testing after pool recovery…")
    results2 = await asyncio.gather(*[_one(i) for i in range(5)])
    ok2  = sum(1 for r in results2 if r[0] == "ok")
    p(GREEN if ok2 == 5 else RED, f"  Recovery: {ok2}/5 OK")
    return {"ok": len(ok), "errors": len(errs), "recovery_ok": ok2}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run_tests():
    r1 = await test_single_latency(8)
    # Let pool reach full capacity before load tests
    p(CYAN, "\n[wait] Letting pool fill to capacity (10s)…")
    await asyncio.sleep(10)
    r2 = await test_concurrent(20)
    p(CYAN, "\n[wait] Letting pool recover (10s)…")
    await asyncio.sleep(10)
    r3 = await test_pool_exhaustion(12)
    r4 = await test_sustained(20.0, rate=4.0)

    p(BOLD + CYAN, "\n" + "="*60)
    p(BOLD, "RESULTS SUMMARY")
    p(BOLD + CYAN, "="*60)
    print(f"  Latency (sequential):   avg={r1['avg']*1000:.0f}ms  errors={r1['errors']}/{r1['n']}")
    print(f"  Concurrent (20):        ok={r2['ok']}/20  errors={r2['errors']}")
    print(f"  Pool exhaustion (24):   ok={r3['ok']}/24  recovery={r3['recovery_ok']}/5")
    print(f"  Sustained (20s,4rps):   ok={r4['ok']}/{r4['total']}  "
          f"rate={r4['ok']/r4['total']*100:.1f}%")

    all_ok = (
        r1['errors'] == 0 and
        r2['ok'] >= 18 and
        r3['recovery_ok'] == 5 and
        r4['ok'] / r4['total'] >= 0.90
    )
    if all_ok:
        p(GREEN + BOLD, "\n✅  STRESS TEST PASSED")
    else:
        p(YELLOW + BOLD, "\nSTRESS TEST PARTIALLY FAILED — see details above")


def main():
    p(BOLD + CYAN, "="*60)
    p(BOLD, "SecureTunnel Stress Test")
    p(BOLD + CYAN, "="*60)

    # ── Start all components ────────────────────────────────────────────────
    try:
        p(CYAN, "\n[startup] Starting exit_node…")
        exit_proc = launch("secure_tunnel.exit_node")
        t = wait_ready(exit_proc, b"[exit] listening", timeout=15)
        p(GREEN, f"  exit_node ready in {t:.1f}s")
        drain_stdout_bg(exit_proc)

        p(CYAN, "[startup] Starting node1…")
        node1_proc = launch("secure_tunnel.node1")
        t = wait_ready(node1_proc, b"[node1] listening", timeout=20)
        p(GREEN, f"  node1 ready in {t:.1f}s")
        drain_stdout_bg(node1_proc)

        p(CYAN, "[startup] Starting socks5_proxy (waiting for tunnel pool)…")
        socks_proc = launch("secure_tunnel.socks5_proxy")
        t = wait_ready(socks_proc, b"[relay] tunnel pool ready", timeout=30)
        p(GREEN, f"  socks5_proxy tunnel pool ready in {t:.1f}s")
        drain_stdout_bg(socks_proc)

        p(CYAN, "[startup] Starting http_proxy…")
        http_proc = launch("secure_tunnel.http_proxy")
        t = wait_ready(http_proc, b"[http_proxy] listening", timeout=10)
        p(GREEN, f"  http_proxy ready in {t:.1f}s\n")
        drain_stdout_bg(http_proc)

    except (TimeoutError, Exception) as e:
        p(RED, f"[startup] FAILED: {e}")
        stop_all()
        return

    # ── Run tests ────────────────────────────────────────────────────────────
    try:
        asyncio.run(run_tests())
    except KeyboardInterrupt:
        p(YELLOW, "\nInterrupted by user.")
    finally:
        p(CYAN, "\n[shutdown] Stopping all processes…")
        stop_all()
        p(GREEN, "Done.")


if __name__ == "__main__":
    main()
