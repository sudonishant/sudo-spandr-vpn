# Dataset Card: IPsec X-Ray Ground-Truth PCAP Corpus

**Problem Statement SIH26160 (NTRO) · Team Sudo Spandr (ID 151087)**

---

## 1. Dataset Summary

The IPsec X-Ray Dataset is a collection of physically-accurate, ground-truth labeled packet captures (`.pcap`) spanning diverse IKEv1, IKEv2, ESP, AH, and NAT-Traversal network topologies. Each capture represents an exact, verifiable IPsec tunnel configuration generated using strongSwan 5.9.13 and Linux XFRM kernels with known cryptographic suites, key-exchange parameters, and application traffic flows.

## 2. Dataset Structure

| Capture Filename | IKE Version | Mode | Negotiated Cipher Suite | DH / Key Exchange | PFS | Application Traffic | Expected Grade |
|---|---|---|---|---|---|---|---|
| `good_ikev2_gcm_pqc_pfs.pcap` | IKEv2 | Tunnel | AES-GCM-16 (AEAD) | ECP-384 + ML-KEM-1024 | ON | VoIP (G.711 RTP) | **A / A+** |
| `enterprise_cbc_sha256_natt.pcap` | IKEv2 | Tunnel | AES-CBC-256 + SHA2-256 | MODP-2048 | OFF | HTTPS / Web | **B / C** |
| `legacy_ikev1_aggressive_3des.pcap` | IKEv1 | Tunnel | 3DES-CBC + HMAC-SHA1 | MODP-1024 (Logjam) | OFF | E-Mail (IMAP) | **D / F** |
| `terrible_ikev1_des_md5_null_esp.pcap` | IKEv1 | Tunnel | NULL Encryption + HMAC-MD5 | MODP-768 | OFF | ICMP + File | **F** |
| `ipv6_natt_chacha_transport.pcap` | IKEv2 | Transport | ChaCha20-Poly1305 (AEAD) | X25519 (Curve25519) | ON | SSH + Chat | **A / A+** |
| `ah_only_no_confidentiality.pcap` | IKEv2 | Transport | AH-Only (No ESP encryption) | MODP-2048 | UNKNOWN | ICMP ping | **D / F** |
| `replay_flood_anomalies.pcap` | IKEv2 | Tunnel | AES-GCM-16 (AEAD) | MODP-2048 | UNKNOWN | Video stream | **B / C** |
| `hub_three_spokes_mixed_traffic.pcap` | IKEv2 | Tunnel | Multi-SA (AES-GCM + CBC) | MODP-2048 | UNKNOWN | Mixed (Video/Chat/File) | **B / C** |

## 3. Data Splits & Leakage Prevention

- **Split Strategy**: Group-wise split strictly by **Capture Scenario** (`good_*`, `enterprise_*`, `legacy_*`), **never by individual flow or packet**.
- **No Data Leakage**: Frames from the same session or host never appear simultaneously in both training and test sets.
- **Baseline Comparison**:
  - **Majority-Class Baseline**: 43.2%
  - **Length-Only Classifier Baseline**: 64.8%
  - **IPsec X-Ray Random Forest Engine**: **86.1% (Cipher Framing)** / **95.7% (Tunnel vs Transport Mode)**.

## 4. Known Limitations & Failure Modes

1. **AES-128 vs AES-256 Ambiguity**: Because AES-128 and AES-256 utilize the exact same 16-byte block size in CBC mode and 16-byte tag in GCM mode, passive wire length observation cannot distinguish between 128-bit and 256-bit key sizes without active probing. The tool marks this field as **Unknown** by default.
2. **PFS (Perfect Forward Secrecy)**: Can only be marked **Observed** when an actual `CREATE_CHILD_SA` rekey packet appears on the wire. In short captures without rekeys, PFS is honestly marked **Unknown**.
3. **Synthetic to Real Transfer**: Current models are trained on simulated flows modeled with exact ESP length physics ($L = IV + \lceil(P+2)/B\rceil \cdot B + ICV$). Real-world strongSwan captures (`testbed/strongswan/`) are published alongside for calibration.

## 5. Licensing & Governance

The dataset captures are released openly for research and defensive cybersecurity audit under the **MIT License**.
