# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('cert.pem', '.'), ('key.pem', '.')],
    hiddenimports=['secure_tunnel.exit_node', 'secure_tunnel.node1', 'secure_tunnel.entry_node', 'secure_tunnel.socks5_proxy', 'secure_tunnel.http_proxy', 'secure_tunnel.tunnel_relay', 'secure_tunnel.crypto', 'secure_tunnel.config', 'secure_tunnel.protocol', 'secure_tunnel.framing', 'secure_tunnel.circuit', 'secure_tunnel.anti_probing', 'secure_tunnel.doh_resolver', 'secure_tunnel.keyring', 'secure_tunnel.key_exchange', 'secure_tunnel.onion_client', 'secure_tunnel.onion', 'secure_tunnel.version', 'secure_tunnel.logging.anon_logger', 'secure_tunnel.transport.tls_in_tls_transport', 'secure_tunnel.ui.kill_switch', 'secure_tunnel.ui.toast', 'secure_tunnel.ui.settings_dialog'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SecureTunnel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
