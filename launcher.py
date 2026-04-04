"""
SecureTunnel GUI Launcher

Startup chain (readiness-based, no fixed delays):
  exit_node   → (listening signal) → node1 (middle)
  node1       → (listening signal) → entry_node
  entry_node  → (listening signal) → socks5_proxy
  socks5_proxy → (pool ready signal) → http_proxy
  http_proxy  → (listening signal) → buttons enabled

Auto-restart: if a process crashes, it is restarted after 2 s.
Pool status: live indicator showing relay/node1 pool fill level.
"""
import sys

# ── PyInstaller frozen-mode subprocess dispatcher ────────────────────────────
# When bundled as SecureTunnel.exe, subprocesses are launched as:
#   SecureTunnel.exe -u -m secure_tunnel.exit_node
# or:
#   SecureTunnel.exe --gen-cert <dir>
# This block intercepts those calls before any GUI code runs.

def _frozen_gen_cert(directory: str) -> None:
    """Generate self-signed TLS cert — runs inside the frozen exe."""
    import datetime, ipaddress
    from pathlib import Path as _P
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    d = _P(directory)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "secure-tunnel")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (d / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ))
    (d / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print("cert.pem and key.pem generated.")


if getattr(sys, 'frozen', False):
    # Force line-buffered stdout so subprocesses flush every print() immediately.
    # PYTHONUNBUFFERED=1 has no effect inside a frozen PyInstaller exe.
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass
    _args = [a for a in sys.argv[1:] if a not in ('-u', '-B', '-O', '-W', 'ignore')]
    if _args and _args[0] == '--gen-cert':
        _frozen_gen_cert(_args[1] if len(_args) > 1 else '.')
        sys.exit(0)
    elif len(_args) >= 2 and _args[0] == '-m':
        import runpy as _runpy
        sys.argv = [sys.argv[0]] + _args[2:]
        _runpy.run_module(_args[1], run_name='__main__', alter_sys=True)
        sys.exit(0)
# ── End dispatcher ────────────────────────────────────────────────────────────

import ctypes
import glob
import io
import os
import secrets as _secrets
import subprocess
import threading
import tkinter as tk
import winreg
from pathlib import Path
from tkinter import scrolledtext

try:
    import pystray
    from PIL import Image, ImageDraw
    _HAS_TRAY = True
except ImportError:
    _HAS_TRAY = False

# HTTP CONNECT proxy for all apps (Telegram, browsers, Steam, etc.)
PROXY_ADDR = "http=127.0.0.1:1081;https=127.0.0.1:1081"
PROXY_OVERRIDE = (
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;"
    "172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;"
    "172.29.*;172.30.*;172.31.*;192.168.*;<local>"
)
_INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

# String in stdout that signals each component is fully ready
_READY_SIGNAL = {
    "secure_tunnel.exit_node":    "[exit] listening",
    "secure_tunnel.node1":        "[node1] listening",
    "secure_tunnel.entry_node":   "[entry] listening",
    "secure_tunnel.socks5_proxy": "[relay] tunnel pool ready",
    "secure_tunnel.http_proxy":   "[http_proxy] listening",
}


def _set_system_proxy(enable: bool) -> None:
    """Enable or disable the Windows system proxy via registry."""
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY,
                        0, winreg.KEY_SET_VALUE) as key:
        if enable:
            winreg.SetValueEx(key, "ProxyServer",   0, winreg.REG_SZ,    PROXY_ADDR)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,    PROXY_OVERRIDE)
            winreg.SetValueEx(key, "ProxyEnable",   0, winreg.REG_DWORD, 1)
        else:
            winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    try:
        import ctypes
        ctypes.windll.wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        ctypes.windll.wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception:
        pass


def _is_system_proxy_active() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _INET_KEY) as key:
            val, _ = winreg.QueryValueEx(key, "ProxyEnable")
            return bool(val)
    except Exception:
        return False


# ── Kill Switch (Windows Firewall) ────────────────────────────────────────────

_KS_RULE = "SecureTunnel-KillSwitch"


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _ks_activate(exe_path: str) -> bool:
    """
    Hard kill switch: block ALL outbound traffic except from SecureTunnel.exe.
    Requires administrator privileges.
    Returns True on success.
    """
    try:
        # 1. Block all outbound
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_KS_RULE}-Block", "dir=out", "action=block",
            "protocol=any",
        ], capture_output=True, check=True)
        # 2. Allow outbound from our own exe (tunnel traffic to nodes + exit→internet)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_KS_RULE}-Allow", "dir=out", "action=allow",
            "protocol=any", f"program={exe_path}",
        ], capture_output=True, check=True)
        return True
    except Exception:
        return False


def _ks_deactivate() -> None:
    """Remove kill switch firewall rules."""
    for suffix in ("-Block", "-Allow"):
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_KS_RULE}{suffix}",
        ], capture_output=True)


def _ks_cleanup() -> None:
    """Called at exit to ensure firewall rules are always removed."""
    _ks_deactivate()


# ── AUTH_SECRET ───────────────────────────────────────────────────────────────

def _ensure_auth_secret(base: Path) -> str:
    """
    Load or generate a per-install AUTH_SECRET.
    Stored in auth_secret.key next to the exe/script.
    Returns the secret string.
    """
    secret_file = base / "auth_secret.key"
    if secret_file.exists():
        return secret_file.read_text().strip()
    secret = _secrets.token_hex(32)
    secret_file.write_text(secret)
    return secret


# ── Tray icon ─────────────────────────────────────────────────────────────────

def _make_tray_icon(color: str = "#0e639c") -> "Image.Image":
    """
    Generate a simple shield-style tray icon (32×32) with the given color.
    color: '#0e639c' = blue (running), '#6c3030' = red (stopped/error).
    """
    size = 32
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    # Draw filled circle as background
    draw.ellipse([2, 2, size - 2, size - 2], fill=color)
    # Draw "S" letter or a lock shape — simple white rectangle as body
    cx, cy = size // 2, size // 2
    # Lock shackle (arc top)
    draw.arc([cx - 5, cy - 10, cx + 5, cy], start=0, end=180, fill="white", width=3)
    # Lock body
    draw.rectangle([cx - 6, cy - 1, cx + 6, cy + 7], fill="white")
    # Keyhole
    draw.ellipse([cx - 2, cy + 1, cx + 2, cy + 5], fill=color)
    return img


# ── Settings persistence ──────────────────────────────────────────────────────

def _load_settings(base: Path) -> dict:
    import json
    f = base / "settings.json"
    if f.exists():
        try:
            return json.loads(f.read_text())
        except Exception:
            pass
    return {}


def _save_settings(base: Path, settings: dict) -> None:
    import json
    f = base / "settings.json"
    f.write_text(json.dumps(settings, indent=2))


# ── Auto-update ───────────────────────────────────────────────────────────────

APP_VERSION = "1.0.0"
_GITHUB_REPO = ""   # Set to "owner/repo" to enable auto-update checks


def _check_update_bg(callback) -> None:
    """
    Check GitHub Releases API for a newer version in a background thread.
    Calls callback(latest_version, download_url) if update is available,
    or callback(None, None) if up-to-date or check failed.
    """
    if not _GITHUB_REPO:
        return

    def _run():
        import urllib.request
        import json as _json
        try:
            url = f"https://api.github.com/repos/{_GITHUB_REPO}/releases/latest"
            req = urllib.request.Request(url, headers={"User-Agent": "SecureTunnel"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = _json.loads(resp.read())
            latest = data.get("tag_name", "").lstrip("v")
            if not latest:
                return
            # Simple version comparison: split by dots
            def ver(s):
                try:
                    return tuple(int(x) for x in s.split("."))
                except Exception:
                    return (0,)
            if ver(latest) > ver(APP_VERSION):
                assets = data.get("assets", [])
                dl_url = next(
                    (a["browser_download_url"] for a in assets
                     if a["name"].endswith(".exe")),
                    data.get("html_url", ""),
                )
                callback(latest, dl_url)
        except Exception:
            pass

    threading.Thread(target=_run, daemon=True).start()


def _write_proxy_pac(base: Path, domains_raw: str) -> None:
    """
    Generate a proxy.pac file for split tunneling.
    domains_raw: newline-separated list of domains/IPs to tunnel.
                 '*' = route everything through proxy.
    """
    socks5_port = 1080
    try:
        s = _load_settings(base)
        socks5_port = s.get("socks5_port", 1080)
    except Exception:
        pass

    lines = [d.strip() for d in domains_raw.splitlines() if d.strip()]
    if not lines or lines == ["*"]:
        # Route everything through proxy
        pac = (
            "function FindProxyForURL(url, host) {\n"
            f'    return "SOCKS5 127.0.0.1:{socks5_port}; DIRECT";\n'
            "}\n"
        )
    else:
        # Build condition for each domain
        checks = []
        for d in lines:
            if d.startswith("*"):
                d = d[1:].lstrip(".")
            checks.append(f'    if (dnsDomainIs(host, ".{d}") || host == "{d}")')
        cond = " ||\n".join(checks)
        pac = (
            "function FindProxyForURL(url, host) {\n"
            f"{cond}\n"
            f'        return "SOCKS5 127.0.0.1:{socks5_port}; DIRECT";\n'
            "    return \"DIRECT\";\n"
            "}\n"
        )
    (base / "proxy.pac").write_text(pac)


# When frozen: use directory of the .exe so cert/key land next to it,
# not inside PyInstaller's temporary extraction folder.
if getattr(sys, 'frozen', False):
    BASE = Path(sys.executable).parent
else:
    BASE = Path(__file__).parent


def _python():
    return sys.executable


class Launcher:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("SecureTunnel Launcher")
        root.resizable(False, False)

        # ── Status bar ──────────────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Idle")
        tk.Label(root, textvariable=self.status_var, font=("Consolas", 10, "bold"),
                 fg="gray").pack(pady=(8, 0))

        # ── Pool indicator ──────────────────────────────────────────────────
        self._relay_pool_var  = tk.StringVar(value="Relay pool: —")
        self._entry_pool_var  = tk.StringVar(value="Entry pool: —")
        self._node1_pool_var  = tk.StringVar(value="Middle pool: —")
        pool_frame = tk.Frame(root)
        pool_frame.pack()
        tk.Label(pool_frame, textvariable=self._relay_pool_var,
                 font=("Consolas", 9), fg="#4ec9b0").pack(side="left", padx=8)
        tk.Label(pool_frame, textvariable=self._entry_pool_var,
                 font=("Consolas", 9), fg="#569cd6").pack(side="left", padx=8)
        tk.Label(pool_frame, textvariable=self._node1_pool_var,
                 font=("Consolas", 9), fg="#ce9178").pack(side="left", padx=8)

        # ── Bandwidth indicator ──────────────────────────────────────────────
        self._bw_var = tk.StringVar(value="↓ — KB/s  ↑ — KB/s")
        tk.Label(root, textvariable=self._bw_var,
                 font=("Consolas", 9, "bold"), fg="#b5cea8").pack()

        tk.Label(
            root,
            text="SOCKS5: 127.0.0.1:1080  |  HTTP Proxy: 127.0.0.1:1081  |  System proxy toggle below",
            font=("Consolas", 9), fg="#9cdcfe",
        ).pack()

        # ── Log area ────────────────────────────────────────────────────────
        self.log = scrolledtext.ScrolledText(
            root, width=80, height=24, state="disabled",
            font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="white"
        )
        self.log.pack(padx=10, pady=6)

        self.log.tag_config("node1",  foreground="#4ec9b0")
        self.log.tag_config("exit",   foreground="#ce9178")
        self.log.tag_config("client", foreground="#9cdcfe")
        self.log.tag_config("socks5", foreground="#9cdcfe")
        self.log.tag_config("info",   foreground="#dcdcaa")
        self.log.tag_config("err",    foreground="#f44747")

        # ── Buttons ─────────────────────────────────────────────────────────
        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=(0, 6))

        self.start_btn = tk.Button(
            btn_frame, text="▶  Start", width=14, bg="#0e639c", fg="white",
            activebackground="#1177bb", relief="flat", command=self.start
        )
        self.start_btn.pack(side="left", padx=6)

        self.stop_btn = tk.Button(
            btn_frame, text="■  Stop", width=14, bg="#6c3030", fg="white",
            activebackground="#8b3a3a", relief="flat", command=self.stop,
            state="disabled"
        )
        self.stop_btn.pack(side="left", padx=6)

        self.chrome_btn = tk.Button(
            btn_frame, text="🌐  Open Chrome", width=16, bg="#2d5a1b", fg="white",
            activebackground="#3a7523", relief="flat", command=self.open_chrome,
            state="disabled"
        )
        self.chrome_btn.pack(side="left", padx=6)

        tk.Button(
            btn_frame, text="📋  Копировать лог", width=18, bg="#3a3a3a", fg="white",
            activebackground="#555555", relief="flat", command=self.copy_log
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame, text="⚙  Настройки", width=14, bg="#3a3a3a", fg="white",
            activebackground="#555555", relief="flat", command=self.open_settings
        ).pack(side="left", padx=6)

        tk.Button(
            btn_frame, text="🔀  Split", width=10, bg="#3a3a3a", fg="white",
            activebackground="#555555", relief="flat", command=self.open_split_tunneling
        ).pack(side="left", padx=6)

        # Second row
        btn_frame2 = tk.Frame(root)
        btn_frame2.pack(pady=(0, 10))

        self._sys_proxy_on = _is_system_proxy_active()
        self._sys_proxy_label = tk.StringVar(
            value=("🔴  Системный прокси: ВКЛ" if self._sys_proxy_on
                   else "⚪  Системный прокси: ВЫКЛ")
        )
        self.sysproxy_btn = tk.Button(
            btn_frame2,
            textvariable=self._sys_proxy_label,
            width=28,
            bg=("#1a5c1a" if self._sys_proxy_on else "#3a3a3a"),
            fg="white",
            activebackground="#2a7a2a",
            relief="flat",
            command=self.toggle_system_proxy,
            state="disabled",
        )
        self.sysproxy_btn.pack(side="left", padx=6)

        # Kill Switch button
        self._ks_on = False
        self._ks_label = tk.StringVar(value="🔓  Kill Switch: ВЫКЛ")
        self._ks_admin = _is_admin()
        self.ks_btn = tk.Button(
            btn_frame2,
            textvariable=self._ks_label,
            width=22,
            bg="#3a3a3a", fg="white",
            activebackground="#555555",
            relief="flat",
            command=self.toggle_kill_switch,
        )
        self.ks_btn.pack(side="left", padx=6)
        if not self._ks_admin:
            self.ks_btn.config(fg="#888888")  # dim if no admin rights

        # Transparent proxy row (shown only if transparent_proxy.exe exists)
        _tproxy_exe = BASE / "transparent_proxy" / "transparent_proxy.exe"
        self._tproxy_available = _tproxy_exe.is_file()
        self._tproxy_exe = _tproxy_exe
        self._tproxy_on = False
        if self._tproxy_available:
            btn_frame3 = tk.Frame(root)
            btn_frame3.pack(pady=(0, 6))
            self._tproxy_label = tk.StringVar(value="⚪  Прозрачный прокси: ВЫКЛ")
            self.tproxy_btn = tk.Button(
                btn_frame3,
                textvariable=self._tproxy_label,
                width=28,
                bg="#3a3a3a", fg="white",
                activebackground="#555555",
                relief="flat",
                command=self.toggle_transparent_proxy,
                state="disabled",
            )
            self.tproxy_btn.pack(padx=6)

        # ── State ────────────────────────────────────────────────────────────
        self.procs: list[subprocess.Popen] = []
        # pid -> (module, tag)
        self._proc_meta: dict[int, tuple[str, str]] = {}
        self._running = False  # True while the tunnel system should be running
        self._log_buf: list[tuple[str, str]] = []
        self._tray = None

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._init_tray()
        # Check for updates in background (non-blocking)
        _check_update_bg(lambda ver, url: self.root.after(
            0, self._notify_update, ver, url
        ))

    # ── Logging ──────────────────────────────────────────────────────────────

    def _append(self, text: str, tag: str = "info"):
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    def log_line(self, line: str, tag: str):
        self._log_buf.append((line, tag))
        if len(self._log_buf) == 1:
            # Schedule a single flush; subsequent calls just append to buf
            self.root.after(16, self._flush_log)  # ~60 fps

    def _flush_log(self):
        if not self._log_buf:
            return
        # Trim log widget if it exceeds 2000 lines to prevent memory/UI slowdown
        line_count = int(self.log.index("end-1c").split(".")[0])
        if line_count > 2000:
            self.log.configure(state="normal")
            self.log.delete("1.0", f"{line_count - 1500}.0")
            self.log.configure(state="disabled")
        self.log.configure(state="normal")
        for text, tag in self._log_buf:
            self.log.insert("end", text, tag)
        self._log_buf.clear()
        self.log.see("end")
        self.log.configure(state="disabled")

    # ── Process streaming ─────────────────────────────────────────────────────

    def _stream(self, proc: subprocess.Popen, tag: str, on_ready=None):
        """
        Read stdout of a subprocess line by line.
        - Forwards each line to the log widget.
        - Fires on_ready() once when the process signals it is ready.
        - Updates pool status indicators.
        - Calls _handle_crash() when the process exits unexpectedly.
        """
        module = self._proc_meta.get(proc.pid, ("unknown", tag))[0]
        signal = _READY_SIGNAL.get(module, "")
        ready_fired = False

        for line in proc.stdout:
            self.log_line(line, tag)

            # Pool status updates
            if "[relay] pool:" in line:
                self.root.after(0, self._update_relay_pool, line.strip())
            elif "[relay] tunnel pool ready" in line:
                self.root.after(0, self._relay_pool_var.set, "Relay pool: ready")
            elif "[relay] bw:" in line:
                self.root.after(0, self._update_bw, line.strip())
            elif "[entry] middle pool:" in line:
                self.root.after(0, self._update_entry_pool, line.strip())
            elif "[node1] exit pool:" in line:
                self.root.after(0, self._update_node1_pool, line.strip())

            # Readiness signal
            if not ready_fired and signal and signal in line:
                ready_fired = True
                if on_ready:
                    self.root.after(0, on_ready)

        # EOF reached — process exited
        if self._running:
            self.root.after(0, self._handle_crash, proc)

    def _update_bw(self, line: str):
        # line: "[relay] bw: 42↓ 18↑ KB/s"
        try:
            part = line.split("bw:")[-1].strip()   # "42↓ 18↑ KB/s"
            self._bw_var.set(f"↓↑ {part}")
        except Exception:
            pass

    def _update_relay_pool(self, line: str):
        # line: "[relay] pool: 8/12 ready"
        try:
            part = line.split("pool:")[-1].strip()  # "8/12 ready"
            self._relay_pool_var.set(f"Relay pool: {part}")
        except Exception:
            pass

    def _update_entry_pool(self, line: str):
        # line: "[entry] middle pool: 8/20 ready"
        try:
            part = line.split("pool:")[-1].strip()
            self._entry_pool_var.set(f"Entry pool: {part}")
        except Exception:
            pass

    def _update_node1_pool(self, line: str):
        # line: "[node1] exit pool: 8/20 ready"
        try:
            part = line.split("pool:")[-1].strip()
            self._node1_pool_var.set(f"Middle pool: {part}")
        except Exception:
            pass

    # ── Process launch ────────────────────────────────────────────────────────

    def _launch(self, module: str, tag: str, on_ready=None) -> subprocess.Popen:
        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        proc = subprocess.Popen(
            [_python(), "-u", "-m", module],
            cwd=str(BASE),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
        )
        self._proc_meta[proc.pid] = (module, tag)
        t = threading.Thread(target=self._stream, args=(proc, tag, on_ready), daemon=True)
        t.start()
        return proc

    def _ensure_cert(self) -> bool:
        cert = BASE / "cert.pem"
        key  = BASE / "key.pem"
        if not cert.exists() or not key.exists():
            self.log_line("[launcher] Generating TLS certificate...\n", "info")
            # Frozen exe: use --gen-cert dispatch; plain Python: run gen_cert.py
            if getattr(sys, 'frozen', False):
                cmd = [_python(), "--gen-cert", str(BASE)]
            else:
                cmd = [_python(), str(BASE / "gen_cert.py")]
            result = subprocess.run(
                cmd,
                cwd=str(BASE),
                capture_output=True, text=True
            )
            if result.returncode != 0:
                self.log_line(f"[launcher] cert gen failed:\n{result.stderr}\n", "err")
                return False
            self.log_line("[launcher] Certificate ready.\n", "info")
        return True

    # ── Startup chain (readiness-based) ──────────────────────────────────────

    @staticmethod
    def _kill_port(port: int) -> None:
        """Kill any process currently listening on the given TCP port (Windows)."""
        try:
            result = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                if f":{port} " in line and "LISTENING" in line:
                    parts = line.split()
                    pid = int(parts[-1])
                    if pid > 0:
                        subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                                       capture_output=True)
        except Exception:
            pass

    def start(self):
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Starting…")
        self._running = True
        self._relay_pool_var.set("Relay pool: —")
        self._entry_pool_var.set("Entry pool: —")
        self._node1_pool_var.set("Middle pool: —")
        self._bw_var.set("↓ — KB/s  ↑ — KB/s")
        self._append("[launcher] Starting SecureTunnel…\n", "info")

        # Kill any stale processes still holding node ports from a previous session
        for port in (8765, 8766, 8767, 1080, 1081):
            self._kill_port(port)

        # Load or generate per-install AUTH_SECRET
        secret = _ensure_auth_secret(BASE)
        os.environ["AUTH_SECRET"] = secret
        self.log_line("[launcher] AUTH_SECRET loaded.\n", "info")

        # Apply custom ports from settings
        s = _load_settings(BASE)
        if s.get("socks5_port"):
            os.environ["SOCKS5_PORT"] = str(s["socks5_port"])
        if s.get("http_port"):
            os.environ["HTTP_PORT"] = str(s["http_port"])
        if s.get("entry_port"):
            os.environ["ENTRY_PORT"] = str(s["entry_port"])
        if s.get("middle_port"):
            os.environ["MIDDLE_PORT"] = str(s["middle_port"])
        if s.get("exit_port"):
            os.environ["EXIT_PORT"] = str(s["exit_port"])

        if not self._ensure_cert():
            self._set_idle()
            return

        self.log_line("[launcher] Waiting for exit node…\n", "info")
        exit_proc = self._launch("secure_tunnel.exit_node", "exit",
                                  on_ready=self._on_exit_ready)
        self.procs = [exit_proc]

    def _on_exit_ready(self):
        if not self._running:
            return
        self.log_line("[launcher] ✔ Exit node ready — starting node1…\n", "info")
        proc = self._launch("secure_tunnel.node1", "node1",
                             on_ready=self._on_node1_ready)
        self.procs.append(proc)

    def _on_node1_ready(self):
        if not self._running:
            return
        self.log_line("[launcher] ✔ Middle node ready — starting entry node…\n", "info")
        proc = self._launch("secure_tunnel.entry_node", "client",
                             on_ready=self._on_entry_ready)
        self.procs.append(proc)

    def _on_entry_ready(self):
        if not self._running:
            return
        self.log_line("[launcher] ✔ Entry node ready — starting SOCKS5 proxy…\n", "info")
        proc = self._launch("secure_tunnel.socks5_proxy", "client",
                             on_ready=self._on_socks5_ready)
        self.procs.append(proc)

    def _on_socks5_ready(self):
        if not self._running:
            return
        self.log_line("[launcher] ✔ Tunnel pool ready — starting HTTP proxy…\n", "info")
        proc = self._launch("secure_tunnel.http_proxy", "client",
                             on_ready=self._on_http_ready)
        self.procs.append(proc)

    def _on_http_ready(self):
        if not self._running:
            return
        self.log_line("[launcher] ✅ All systems ready!\n", "info")
        self.status_var.set("✅ Running")
        self.chrome_btn.config(state="normal")
        self.sysproxy_btn.config(state="normal")
        self._ks_on_tunnel_up()
        self._tray_set(self._tray_icon_running if _HAS_TRAY else None,
                       "SecureTunnel — Running")
        if self._tproxy_available:
            self.tproxy_btn.config(state="normal")
            self.log_line(
                "[launcher] transparent_proxy.exe обнаружен — "
                "прозрачный прокси доступен (требует прав администратора).\n",
                "info",
            )

    # ── Auto-restart on crash ─────────────────────────────────────────────────

    def _handle_crash(self, dead_proc: subprocess.Popen):
        """Called from main thread when a process stdout stream hits EOF."""
        if not self._running:
            return
        meta = self._proc_meta.get(dead_proc.pid)
        if meta is None:
            return
        module, tag = meta
        code = dead_proc.returncode
        self.log_line(
            f"[launcher] ⚠ {module.split('.')[-1]} exited (code {code}) — restarting in 2 s…\n",
            "err"
        )
        self.status_var.set(f"⚠ {module.split('.')[-1]} crashed — restarting…")
        if dead_proc in self.procs:
            self.procs.remove(dead_proc)
        self._proc_meta.pop(dead_proc.pid, None)  # free stale entry
        self._ks_on_tunnel_down()
        self._tray_set(self._tray_icon_error if _HAS_TRAY else None,
                       f"SecureTunnel — ⚠ {module.split('.')[-1]} crashed")
        self.root.after(2000, lambda: self._restart_proc(module, tag))

    def _restart_proc(self, module: str, tag: str):
        if not self._running:
            return
        self.log_line(f"[launcher] ↺ Restarting {module.split('.')[-1]}…\n", "info")
        proc = self._launch(module, tag)
        self.procs.append(proc)
        self.status_var.set("✅ Running")

    # ── Copy log ──────────────────────────────────────────────────────────────

    def copy_log(self):
        text = self.log.get("1.0", "end-1c")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.log_line("[launcher] Лог скопирован в буфер обмена.\n", "info")

    # ── Settings dialog ───────────────────────────────────────────────────────

    def open_settings(self):
        """Open a modal settings dialog for configuring ports."""
        if self._running:
            self.log_line("[launcher] Останови туннель перед изменением настроек.\n", "err")
            return
        dlg = tk.Toplevel(self.root)
        dlg.title("Настройки SecureTunnel")
        dlg.resizable(False, False)
        dlg.grab_set()
        dlg.configure(bg="#252526")

        settings = _load_settings(BASE)

        fields = [
            ("SOCKS5 порт",   "socks5_port",  str(settings.get("socks5_port", 1080))),
            ("HTTP порт",     "http_port",    str(settings.get("http_port",   1081))),
            ("Entry порт",    "entry_port",   str(settings.get("entry_port",  8765))),
            ("Middle порт",   "middle_port",  str(settings.get("middle_port", 8766))),
            ("Exit порт",     "exit_port",    str(settings.get("exit_port",   8767))),
        ]

        entries = {}
        for row, (label, key, default) in enumerate(fields):
            tk.Label(dlg, text=label, bg="#252526", fg="#d4d4d4",
                     font=("Consolas", 9), anchor="w", width=16).grid(
                row=row, column=0, padx=10, pady=4, sticky="w")
            var = tk.StringVar(value=default)
            e = tk.Entry(dlg, textvariable=var, width=8, bg="#3c3c3c", fg="white",
                         insertbackground="white", relief="flat",
                         font=("Consolas", 9))
            e.grid(row=row, column=1, padx=10, pady=4)
            entries[key] = var

        def save():
            new = {}
            for key, var in entries.items():
                try:
                    val = int(var.get())
                    if not (1 <= val <= 65535):
                        raise ValueError
                    new[key] = val
                except ValueError:
                    self.log_line(f"[launcher] Неверный порт для {key}.\n", "err")
                    return
            _save_settings(BASE, new)
            self.log_line("[launcher] Настройки сохранены. Применятся при следующем запуске.\n", "info")
            dlg.destroy()

        def reset():
            defaults = {"socks5_port": 1080, "http_port": 1081,
                        "entry_port": 8765, "middle_port": 8766, "exit_port": 8767}
            for key, var in entries.items():
                var.set(str(defaults[key]))

        btn_frame = tk.Frame(dlg, bg="#252526")
        btn_frame.grid(row=len(fields), column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Сохранить", command=save,
                  bg="#0e639c", fg="white", relief="flat", width=12).pack(side="left", padx=6)
        tk.Button(btn_frame, text="По умолчанию", command=reset,
                  bg="#3a3a3a", fg="white", relief="flat", width=14).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Отмена", command=dlg.destroy,
                  bg="#3a3a3a", fg="white", relief="flat", width=10).pack(side="left", padx=6)

    # ── Split tunneling ───────────────────────────────────────────────────────

    def open_split_tunneling(self):
        """
        Split tunneling: set proxy only for selected apps via per-app proxy env vars.
        Shows running processes; user picks which ones route through tunnel.
        Implementation: writes a proxy.pac file and optionally sets system PAC URL.
        """
        dlg = tk.Toplevel(self.root)
        dlg.title("Split Tunneling — выбор приложений")
        dlg.resizable(True, True)
        dlg.grab_set()
        dlg.configure(bg="#252526")
        dlg.geometry("500x400")

        tk.Label(
            dlg,
            text="Split tunneling настраивает системный прокси через PAC-файл.\n"
                 "Выбери домены/IP которые должны идти через туннель:",
            bg="#252526", fg="#d4d4d4", font=("Consolas", 9), justify="left",
        ).pack(padx=10, pady=8, anchor="w")

        settings = _load_settings(BASE)
        tunnel_domains_raw = settings.get("tunnel_domains", "")

        tk.Label(dlg, text="Домены через туннель (по одному на строку, * для всех):",
                 bg="#252526", fg="#9cdcfe", font=("Consolas", 9)).pack(padx=10, anchor="w")

        txt = tk.Text(dlg, height=12, bg="#1e1e1e", fg="#d4d4d4",
                      font=("Consolas", 9), insertbackground="white", relief="flat")
        txt.pack(padx=10, pady=4, fill="both", expand=True)
        txt.insert("1.0", tunnel_domains_raw)

        def save_split():
            domains_text = txt.get("1.0", "end-1c").strip()
            settings["tunnel_domains"] = domains_text
            _save_settings(BASE, settings)
            # Write proxy.pac
            _write_proxy_pac(BASE, domains_text)
            self.log_line("[launcher] Split tunneling сохранён → proxy.pac обновлён.\n", "info")
            dlg.destroy()

        tk.Button(dlg, text="Сохранить", command=save_split,
                  bg="#0e639c", fg="white", relief="flat").pack(pady=6)

    # ── Kill Switch ───────────────────────────────────────────────────────────

    def toggle_kill_switch(self):
        if not self._ks_admin:
            self.log_line(
                "[launcher] ⚠ Kill Switch требует прав администратора. "
                "Запусти SecureTunnel.exe от имени администратора.\n", "err"
            )
            return
        self._ks_on = not self._ks_on
        if self._ks_on:
            self._ks_apply()
        else:
            self._ks_remove()

    def _ks_apply(self):
        """Activate kill switch: block all outbound except from our exe."""
        exe = str(Path(sys.executable).resolve())
        ok = _ks_activate(exe)
        if ok:
            self._ks_label.set("🔒  Kill Switch: ВКЛ")
            self.ks_btn.config(bg="#7a1a1a")
            self.log_line(
                "[launcher] 🔒 Kill Switch ВКЛЮЧЁН — весь трафик заблокирован, "
                "кроме туннеля.\n", "info"
            )
        else:
            self._ks_on = False
            self.log_line("[launcher] Kill Switch: ошибка применения правил.\n", "err")

    def _ks_remove(self):
        """Deactivate kill switch."""
        _ks_deactivate()
        self._ks_on = False
        self._ks_label.set("🔓  Kill Switch: ВЫКЛ")
        self.ks_btn.config(bg="#3a3a3a")
        self.log_line("[launcher] 🔓 Kill Switch ВЫКЛЮЧЕН — прямой доступ разрешён.\n", "info")

    def _ks_on_tunnel_down(self):
        """Called when a node crashes while kill switch is active."""
        if self._ks_on:
            self.log_line(
                "[launcher] 🔒 Kill Switch активен — трафик заблокирован до "
                "восстановления туннеля.\n", "info"
            )

    def _ks_on_tunnel_up(self):
        """Called when tunnel is fully up (all nodes ready)."""
        if self._ks_on:
            self.log_line(
                "[launcher] 🔒 Kill Switch: туннель восстановлен, "
                "трафик снова идёт через туннель.\n", "info"
            )

    # ── System proxy toggle ───────────────────────────────────────────────────

    def toggle_system_proxy(self):
        self._sys_proxy_on = not self._sys_proxy_on
        try:
            _set_system_proxy(self._sys_proxy_on)
        except Exception as e:
            self.log_line(f"[launcher] System proxy error: {e}\n", "err")
            self._sys_proxy_on = not self._sys_proxy_on
            return
        if self._sys_proxy_on:
            self._sys_proxy_label.set("🔴  Системный прокси: ВКЛ")
            self.sysproxy_btn.config(bg="#1a5c1a")
            self.log_line("[launcher] System proxy ENABLED — all apps now use 127.0.0.1:1081\n", "info")
        else:
            self._sys_proxy_label.set("⚪  Системный прокси: ВЫКЛ")
            self.sysproxy_btn.config(bg="#3a3a3a")
            self.log_line("[launcher] System proxy DISABLED.\n", "info")

    # ── Transparent proxy toggle ──────────────────────────────────────────────

    def toggle_transparent_proxy(self):
        if not self._tproxy_available:
            return
        if not self._tproxy_on:
            # Start transparent_proxy.exe (requires admin rights)
            try:
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"
                proc = subprocess.Popen(
                    [str(self._tproxy_exe)],
                    cwd=str(self._tproxy_exe.parent),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    env=env,
                )
                self._proc_meta[proc.pid] = ("transparent_proxy", "info")
                t = threading.Thread(
                    target=self._stream, args=(proc, "info", None), daemon=True
                )
                t.start()
                self.procs.append(proc)
                self._tproxy_on = True
                self._tproxy_label.set("🔴  Прозрачный прокси: ВКЛ")
                self.tproxy_btn.config(bg="#1a5c1a")
                self.log_line(
                    "[launcher] Прозрачный прокси запущен — "
                    "все TCP-соединения перехватываются без прокси-настроек.\n",
                    "info",
                )
            except Exception as e:
                self.log_line(f"[launcher] Ошибка запуска transparent proxy: {e}\n", "err")
        else:
            # Stop transparent proxy process
            for p in list(self.procs):
                meta = self._proc_meta.get(p.pid)
                if meta and meta[0] == "transparent_proxy":
                    try:
                        p.terminate()
                    except Exception:
                        pass
                    self.procs.remove(p)
                    self._proc_meta.pop(p.pid, None)
                    break
            self._tproxy_on = False
            self._tproxy_label.set("⚪  Прозрачный прокси: ВЫКЛ")
            self.tproxy_btn.config(bg="#3a3a3a")
            self.log_line("[launcher] Прозрачный прокси остановлен.\n", "info")

    # ── Chrome launcher ───────────────────────────────────────────────────────

    @staticmethod
    def _find_chrome() -> str | None:
        candidates = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
        local = os.environ.get("LOCALAPPDATA", "")
        if local:
            candidates.append(os.path.join(local, r"Google\Chrome\Application\chrome.exe"))
        for path in candidates:
            if os.path.isfile(path):
                return path
        for pattern in [
            r"C:\Program Files*\Google\Chrome\Application\chrome.exe",
            os.path.join(os.environ.get("LOCALAPPDATA", ""), r"Google\Chrome\**\chrome.exe"),
        ]:
            matches = glob.glob(pattern, recursive=True)
            if matches:
                return matches[0]
        return None

    def open_chrome(self):
        chrome = self._find_chrome()
        if not chrome:
            self.log_line("[launcher] Chrome not found on this PC.\n", "err")
            return
        profile_dir = str(BASE / "chrome_profile")
        subprocess.Popen([
            chrome,
            "--proxy-server=socks5://127.0.0.1:1080",
            f"--user-data-dir={profile_dir}",
            "--no-first-run",
            "--no-default-browser-check",
        ])
        self.log_line("[launcher] Chrome opened with SOCKS5 proxy.\n", "info")

    # ── Stop ──────────────────────────────────────────────────────────────────

    def stop(self):
        self._running = False
        self._append("[launcher] Stopping all processes…\n", "info")
        for p in self.procs:
            try:
                p.terminate()
            except Exception:
                pass
        self.procs.clear()
        if self._sys_proxy_on:
            try:
                _set_system_proxy(False)
                self._sys_proxy_on = False
                self._sys_proxy_label.set("⚪  Системный прокси: ВЫКЛ")
                self.sysproxy_btn.config(bg="#3a3a3a")
                self.log_line("[launcher] System proxy automatically disabled.\n", "info")
            except Exception:
                pass
        # Deactivate kill switch on stop so traffic isn't blocked after exit
        if self._ks_on:
            self._ks_remove()
        self._tray_set(self._tray_icon_idle if _HAS_TRAY else None,
                       "SecureTunnel — Idle")
        self._relay_pool_var.set("Relay pool: —")
        self._entry_pool_var.set("Entry pool: —")
        self._node1_pool_var.set("Middle pool: —")
        self._bw_var.set("↓ — KB/s  ↑ — KB/s")
        if self._tproxy_available:
            self._tproxy_on = False
            self._tproxy_label.set("⚪  Прозрачный прокси: ВЫКЛ")
            self.tproxy_btn.config(bg="#3a3a3a", state="disabled")
        self._set_idle()

    def _set_idle(self):
        self.status_var.set("Idle")
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.chrome_btn.config(state="disabled")
        self.sysproxy_btn.config(state="disabled")

    def _on_close(self):
        """Minimize to tray instead of quitting (if tray is available)."""
        if _HAS_TRAY and self._tray is not None:
            self.root.withdraw()   # hide window, keep running in tray
        else:
            self._quit_app()

    def _quit_app(self):
        self.stop()
        if _HAS_TRAY and self._tray is not None:
            self._tray.stop()
        self.root.destroy()

    # ── Tray ─────────────────────────────────────────────────────────────────

    def _init_tray(self):
        if not _HAS_TRAY:
            return
        self._tray_icon_idle    = _make_tray_icon("#555555")
        self._tray_icon_running = _make_tray_icon("#0e639c")
        self._tray_icon_error   = _make_tray_icon("#6c3030")

        menu = pystray.Menu(
            pystray.MenuItem("Показать", self._tray_show, default=True),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("▶  Start",  lambda: self.root.after(0, self.start)),
            pystray.MenuItem("■  Stop",   lambda: self.root.after(0, self.stop)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("✕  Выйти", lambda: self.root.after(0, self._quit_app)),
        )
        self._tray = pystray.Icon(
            "SecureTunnel",
            self._tray_icon_idle,
            "SecureTunnel — Idle",
            menu,
        )
        t = threading.Thread(target=self._tray.run, daemon=True)
        t.start()

    def _tray_show(self, *_):
        self.root.after(0, self._show_window)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _notify_update(self, version: str, url: str):
        self.log_line(
            f"[launcher] 🔔 Доступна новая версия SecureTunnel v{version}!\n"
            f"[launcher] Скачай: {url}\n",
            "info"
        )

    def _tray_set(self, icon_img, tooltip: str):
        if not _HAS_TRAY or self._tray is None:
            return
        self._tray.icon  = icon_img
        self._tray.title = tooltip


def main():
    import atexit
    atexit.register(_ks_cleanup)  # always remove firewall rules on exit
    root = tk.Tk()
    Launcher(root)
    root.mainloop()


if __name__ == "__main__":
    main()
