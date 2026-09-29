# 🛡️ SUDO SPANDR — C4I Military Grade VPN Sentinel & Security Command Center

An autonomous, zero-decryption VPN tunnel detector, 5-factor privacy audit engine, and cryptographic protocol recommendation command center designed for **SIH 2026 (Problem Statement SIH26160)**.

---

## ⚡ Core Features

- **Autonomous VPN Detection**: Identifies active tunnels (`tun`, `tap`, `wg`, `tailscale`, `warp`, `zt`) and running daemons (WireGuard, OpenVPN, StrongSwan IPsec, Tailscale, Tor, Proton, NordLynx).
- **5-Factor Deep Security Audit**: Strict alignment with NIST SP 800-77 & RFC 8221 standards (Tunnel integrity, ISP snooping, DNS hijack risk, IPv6 leakage, and WebRTC exposure).
- **"Kaun Sa Accha Rahega" Protocol Advisor**: Real-time smart recommendation engine comparing WireGuard, Tailscale, IPsec IKEv2, OpenVPN Stealth, and Shadowsocks/V2Ray.
- **Geospatial Triangulation Radar**: Interactive dark Leaflet cyber map pinpointing public exposure coordinates.
- **Real-Time Global Latency Probes**: Live TCP handshake benchmarks across Cloudflare Anycast, Google DNS, Quad9 Switzerland, and Mullvad Sweden.
- **Live Bidirectional WebSocket Sync**: 2-second real-time streaming updates without page reload.
- **One-Click Emergency Tools**: Built-in DNS cache flush and deployment configuration generators.

---

## 🚀 Quick Start

### 1. Requirements
- Python ≥ 3.10
- Dependencies: `fastapi`, `uvicorn`, `scapy`

### 2. Launch
```bash
./run.sh
```
Open **[http://localhost:8050](http://localhost:8050)** in your browser.
API Swagger documentation is accessible at **[http://localhost:8050/docs](http://localhost:8050/docs)**.
