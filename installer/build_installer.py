"""
SecureTunnel installer builder.

Runs on your Windows dev machine. Produces dist/SecureTunnelSetup.exe

Requirements (install once):
    pip install pyinstaller
    winget install JRSoftware.InnoSetup      # or download from jrsoftware.org

Usage:
    python installer/build_installer.py
"""

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DIST = ROOT / "dist"
SPEC = ROOT / "installer" / "SecureTunnel.spec"
ISS  = ROOT / "installer" / "setup.iss"


def step(msg: str) -> None:
    print(f"\n{'─'*60}\n  {msg}\n{'─'*60}")


def run(cmd: list, **kwargs) -> None:
    print(f"$ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"ERROR: command failed (code {result.returncode})")
        sys.exit(result.returncode)


def check_tools() -> tuple[Path, Path | None]:
    """Return (pyinstaller_path, iscc_path|None)."""
    # PyInstaller
    pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("PyInstaller not found. Installing...")
        run([sys.executable, "-m", "pip", "install", "pyinstaller"])
        pyinstaller = shutil.which("pyinstaller")
    if not pyinstaller:
        print("ERROR: pyinstaller not found after install.")
        sys.exit(1)

    # Inno Setup (optional — only needed for .exe installer wrapper)
    iscc_candidates = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
        shutil.which("ISCC") or "",
    ]
    iscc = next((Path(p) for p in iscc_candidates if p and Path(p).exists()), None)

    return Path(pyinstaller), iscc


def build_exe(pyinstaller: Path) -> Path:
    step("Step 1/2 — Building SecureTunnel.exe with PyInstaller")
    run([
        str(pyinstaller),
        str(SPEC),
        "--distpath", str(DIST),
        "--workpath", str(ROOT / "build"),
        "--noconfirm",
    ])
    exe = DIST / "SecureTunnel.exe"
    if not exe.exists():
        print("ERROR: SecureTunnel.exe not found after build.")
        sys.exit(1)
    size_mb = exe.stat().st_size / 1024 / 1024
    print(f"  Built: {exe}  ({size_mb:.1f} MB)")
    return exe


def build_installer(iscc: Path) -> Path:
    step("Step 2/2 — Building SecureTunnelSetup.exe with Inno Setup")
    run([str(iscc), str(ISS)])
    setup_exe = DIST / "SecureTunnelSetup.exe"
    if not setup_exe.exists():
        print("ERROR: SecureTunnelSetup.exe not found.")
        sys.exit(1)
    size_mb = setup_exe.stat().st_size / 1024 / 1024
    print(f"  Built: {setup_exe}  ({size_mb:.1f} MB)")
    return setup_exe


def main() -> None:
    print("\n  SecureTunnel Installer Builder")
    print("  ================================\n")

    DIST.mkdir(exist_ok=True)

    pyinstaller, iscc = check_tools()

    exe = build_exe(pyinstaller)

    if iscc:
        setup_exe = build_installer(iscc)
        final = setup_exe
    else:
        print("\n  Inno Setup not found — skipping installer wrapper.")
        print("  You can distribute SecureTunnel.exe directly.")
        print("  To build a proper installer, install Inno Setup 6:")
        print("  winget install JRSoftware.InnoSetup")
        final = exe

    print(f"""
{'═'*60}
  BUILD COMPLETE
{'═'*60}
  Output: {final}
  Size:   {final.stat().st_size / 1024 / 1024:.1f} MB

  Distribution:
  • Share {final.name} with users
  • User downloads → double-clicks → installed, shortcut on desktop
  • No Python, no terminal, no manual steps required
{'═'*60}
""")


if __name__ == "__main__":
    main()
