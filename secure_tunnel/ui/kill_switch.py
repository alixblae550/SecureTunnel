"""
Windows Firewall Kill Switch.

Blocks ALL outbound traffic except from the SecureTunnel executable.
Requires administrator privileges to activate/deactivate.

Usage:
    from secure_tunnel.ui.kill_switch import activate, deactivate, cleanup, is_admin

    if is_admin():
        ok = activate(exe_path)
    ...
    deactivate()   # always safe to call even if not activated
"""
import subprocess

_KS_RULE = "SecureTunnel-KillSwitch"


def is_admin() -> bool:
    """Return True if the current process has administrator privileges."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def activate(exe_path: str) -> bool:
    """
    Activate the kill switch:
      1. Block ALL outbound traffic.
      2. Allow outbound only from exe_path (the tunnel process).

    Returns True on success, False if netsh failed or insufficient privileges.
    """
    try:
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_KS_RULE}-Block", "dir=out", "action=block",
            "protocol=any",
        ], capture_output=True, check=True)
        subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={_KS_RULE}-Allow", "dir=out", "action=allow",
            "protocol=any", f"program={exe_path}",
        ], capture_output=True, check=True)
        return True
    except Exception:
        return False


def deactivate() -> None:
    """Remove kill switch firewall rules (always safe to call)."""
    for suffix in ("-Block", "-Allow"):
        subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={_KS_RULE}{suffix}",
        ], capture_output=True)


def cleanup() -> None:
    """Alias for deactivate() — intended for atexit registration."""
    deactivate()
