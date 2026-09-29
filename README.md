# 🛡️ SUDO SPANDR — Military C4I VPN Sentinel & Security Command Center

<div align="center">

![GitHub Repo stars](https://img.shields.io/badge/Status-Operational-10b981?style=for-the-badge)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=for-the-badge&logo=python)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css)
![Leaflet](https://img.shields.io/badge/Leaflet-199900?style=for-the-badge&logo=Leaflet)

**Smart India Hackathon (SIH 2026) · Problem Statement SIH26160 (NTRO) · Team Sudo Spandr**

*An autonomous, zero-decryption VPN tunnel detector, 5-factor NIST privacy auditor, real-time multi-node latency benchmark engine, and intelligent protocol recommendation command center.*

[Features](#-key-features) • [Architecture](#-architecture) • [Security Checks](#-5-factor-deep-security-audit) • [Quick Start](#-quick-start) • [API Specs](#-api-endpoints)

</div>

---

## 📖 Overview

**Sudo Spandr** takes a passive, zero-wait inspection approach to endpoint security. Without requiring decryption keys, invasive root certificate installations, or payload tampering, it continuously audits your operating system's kernel network interfaces, routing tables, and cryptographic daemons to determine:
1. **Whether your internet traffic is genuinely protected by an encrypted tunnel or leaking in the clear.**
2. **Exactly what your Internet Service Provider (ISP), upstream transit providers, and state actors can see** (e.g. SNI headers, DNS queries, physical location triangulation).
3. **Which VPN protocol is objectively best suited for your current connection speed, latency, and operational use-case** (*"Kaun Sa Accha Rahega"*).

---

## ⚡ Key Features (15+ Cyber Capabilities)

### 1. 🔍 Autonomous Tunnel & Process Detector
- Identifies kernel virtual interfaces: `tun*`, `tap*`, `wg*`, `ppp*`, `tailscale*`, `zt*`, `xfrm*`, `proton*`, `mullvad*`.
- Scans system process trees for active VPN daemons: **WireGuard**, **OpenVPN**, **StrongSwan (IPsec)**, **Tailscale**, **Tor Onion Router**, **Cloudflare WARP**, **ZeroTier**, and commercial clients.
- Verifies default routing gateway and egress device bindings.

### 2. 🛡️ 5-Factor Deep Security Audit Engine (NIST SP 800-77 & RFC 8221)
- **Tunnel Integrity [CHK_TUNNEL]**: Verifies if outbound payload is encapsulated or exposed in cleartext.
- **ISP Data Profiling [CHK_ISP]**: Detects domestic telecom providers (Reliance Jio, Airtel, etc.) and flags potential metadata profiling.
- **DNS Leak & Hijack Guard [CHK_DNS]**: Audits `/etc/resolv.conf` resolvers to prevent unencrypted UDP 53 leaks.
- **Dual-Stack IPv6 Leak Shield [CHK_IPV6]**: Checks whether parallel IPv6 routes bypass IPv4-only tunnels.
- **Browser WebRTC STUN Leak [CHK_WEBRTC]**: Evaluates browser WebRTC NAT-traversal exposure vectors.

### 3. 🧠 "Kaun Sa Accha Rahega" — Protocol Intelligence Engine
Compares and recommends modern VPN protocols tailored to your current connection:
- **WireGuard**: ChaCha20-Poly1305 + Curve25519 (Ultra-fast, lowest latency overhead, ideal for Gaming & 4K/8K streaming).
- **Tailscale / Headscale**: Zero-config mesh over WireGuard Noise protocol with NAT/CGNAT traversal (ideal for PC-to-Mobile and remote server access without port forwarding).
- **IPsec IKEv2 / MOBIKE**: CNSA 2.0 / NIST compliant with hardware XFRM offloading (ideal for Enterprise, Banking, and Defense intranets).
- **OpenVPN Cloaked TCP-443**: TLS-Crypt camouflage (ideal for bypassing university, hostel, and strict corporate firewalls).
- **Shadowsocks / V2Ray (VLESS-XTLS)**: Anti-DPI censorship evasion protocol that mimics legitimate HTTPS traffic.

### 4. 🗺️ Geospatial Triangulation & Pinpoint Radar Map
- Integrated interactive **Leaflet dark cyber map**.
- Displays public IP geolocation, coordinates (Latitude/Longitude), ASN metadata, and estimated physical exposure radius.

### 5. ⚡ Real-Time Global Multi-Node Latency Probes
- Live TCP handshake latency tests against:
  - **Cloudflare Anycast** (`1.1.1.1:53`)
  - **Google Global DNS** (`8.8.8.8:53`)
  - **Quad9 Swiss Enclave** (`9.9.9.9:53`)
  - **Mullvad Privacy Relay** (`mullvad.net:443`)
  - **ProtonVPN Core** (`proton.me:443`)

### 6. 🔄 Live Bidirectional WebSocket Sync (2s Ticks)
- Connects to `/ws/live`. Any network change (connecting or disconnecting a VPN) dynamically updates the dashboard in under 2 seconds without refreshing the page.

### 7. 🧹 One-Click Emergency Utilities
- **Flush DNS Cache**: Instant resolver cache flushing via `systemd-resolve` or `resolvectl`.
- **Config Template Viewer**: In-app modal with copyable client/server configuration templates.
- **One-Click Deployment Commands**: Direct terminal snippets ready to paste.

### 8. 📊 Kernel Interfaces & Routing Table Inspector
- Real-time tabular inspector displaying MTU sizes, MAC hardware addresses, operational states (`UP`/`DOWN`), destination subnets, and routing metrics.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 SUDO SPANDR COMMAND CENTER                  │
└─────────────────────────────────────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            ▼                                     ▼
┌────────────────────────┐              ┌───────────────────┐
│     FastAPI Backend    │              │ Frontend Cyber HUD│
│ (Port 8050 / Python 3) │              │ (Tailwind + Leaf) │
└───────────┬────────────┘              └─────────┬─────────┘
            │                                     │
   ┌────────┴────────┐                   ┌────────┴─────────┐
   ▼                 ▼                   ▼                  ▼
System Probes   Audit Engine       Live Map Radar     Advisor HUD
(ip route,      (5-Factor NIST     (GeoIP Pinpoint)   (Configs, Probes,
 /etc/resolv,   Checklist &                           Copy Commands)
 processes)     Penalties)
            ▲
            │ (WebSocket /ws/live - 2s Heartbeat)
            └─────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Step 1: Clone Repository
```bash
git clone https://github.com/sudonishant/sudo-spandr.git
cd sudo-spandr
```

### Step 2: Launch with One Command
```bash
./run.sh
```

The script automatically:
- Verifies system dependencies (`python3`, `fastapi`, `uvicorn`).
- Frees port `8050` if occupied.
- Boots the FastAPI ASGI server with WebSockets enabled.

### Step 3: Open in Browser
- 🌐 **Dashboard UI**: [http://localhost:8050](http://localhost:8050)
- 📚 **Swagger OpenAPI Docs**: [http://localhost:8050/docs](http://localhost:8050/docs)
- 📖 **ReDoc Documentation**: [http://localhost:8050/redoc](http://localhost:8050/redoc)

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/status` | Complete system health, active VPN tunnel, and identity state |
| `GET` | `/api/audit` | Deep 5-factor security audit with penalty scores and NIST verdict |
| `GET` | `/api/vpn/recommendations` | Tailored protocol recommendations with configuration templates |
| `GET` | `/api/ping-test` | Multi-node TCP latency probes across global privacy endpoints |
| `GET` | `/api/interfaces` | Kernel socket adapters, MTUs, MAC addresses, and states |
| `GET` | `/api/routes` | System IP routing table with gateways and metrics |
| `POST` | `/api/tools/flush-dns` | Flush local system resolver cache |
| `WS` | `/ws/live` | Bidirectional real-time stream (2-second interval telemetry) |

---

## 👥 Authors & Credits

- **Team Sudo Spandr** (ID 151087)
- **Hackathon**: Smart India Hackathon (SIH 2026)
- **Ministry / Organization**: National Technical Research Organisation (NTRO)
- **Problem Statement**: SIH26160 — Passive IPsec & Encrypted VPN Security Analysis

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
