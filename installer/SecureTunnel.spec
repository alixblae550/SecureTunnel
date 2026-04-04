# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — bundles SecureTunnel into a single .exe
# Build: pyinstaller installer/SecureTunnel.spec

from pathlib import Path

ROOT = Path(SPECPATH).parent  # project root

a = Analysis(
    [str(ROOT / 'launcher.py')],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[
        (str(ROOT / 'secure_tunnel'), 'secure_tunnel'),
    ],
    hiddenimports=[
        # Node modules
        'secure_tunnel.exit_node',
        'secure_tunnel.node1',
        'secure_tunnel.entry_node',
        'secure_tunnel.tunnel_relay',
        'secure_tunnel.socks5_proxy',
        'secure_tunnel.http_proxy',
        'secure_tunnel.doh_resolver',
        'secure_tunnel.crypto',
        'secure_tunnel.framing',
        'secure_tunnel.protocol',
        'secure_tunnel.anti_probing',
        'secure_tunnel.circuit',
        'secure_tunnel.config',
        'secure_tunnel.keyring',
        'secure_tunnel.transport.tls_in_tls_transport',
        'secure_tunnel.logging.anon_logger',
        # Cryptography
        'cryptography',
        'cryptography.hazmat.primitives.asymmetric.x25519',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.ciphers.aead',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.kdf.hkdf',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.x509',
        'cryptography.x509.oid',
        # ML-KEM (post-quantum) — available when cryptography is built against OpenSSL >= 3.5
        # Safe to include: crypto.py catches ImportError and falls back to X25519-only
        'cryptography.hazmat.primitives.asymmetric.mlkem',
        # Msgpack
        'msgpack',
        # Keyring (Windows backend)
        'keyring',
        'keyring.backends.Windows',
        'keyring.backends.fail',
        # Tray icon
        'pystray',
        'pystray._win32',
        'PIL',
        'PIL.Image',
        'PIL.ImageDraw',
        # Stdlib
        'tkinter',
        'tkinter.scrolledtext',
        'asyncio',
        'ssl',
        'winreg',
        'runpy',
        'ipaddress',
    ],
    excludes=[
        'matplotlib', 'numpy', 'scipy', 'pandas',
        'cv2', 'PyQt5', 'wx', 'PySide2',
        'IPython', 'jupyter', 'notebook',
    ],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name='SecureTunnel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # no console window — GUI only
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    uac_admin=False,
    onefile=True,
)
