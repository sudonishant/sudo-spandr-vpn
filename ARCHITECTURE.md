# IPsec X-Ray: System Architecture & Design Specification

**Problem Statement 26160 (NTRO) · Smart India Hackathon 2026**  
**Team Sudo Spandr (Team ID: 151087)**  
*Autonomous Zero-Decryption IPsec Passive Analyzer & Compliance Assessment Framework*

---

## 1. Executive Summary & Design Philosophy

IPsec X-Ray analyzes live or recorded IPsec traffic (IKEv1, IKEv2, ESP, AH, NAT-T) **without holding private keys, without decrypting payloads, and without packet injection**.

Traditional VPN monitors rely on host-level introspection (`ip route`, `ps aux`, endpoint agents) or active probing. In contested C4I networks and cross-border SIGINT operations, host access is prohibited and active probes compromise stealth. IPsec X-Ray solves this by operating strictly out-of-band on raw wire-level captures (`libpcap`), combining RFC-compliant packet dissection with **packet-length physics** and **calibrated Random Forest ensembles**.

```
                ┌──────────────────────────────────────────────┐
                │          RAW PCAP / LIVE INTERFACE           │
                │        (UDP 500, 4500 | IP Proto 50, 51)     │
                └──────────────────────┬───────────────────────┘
                                       │
                                       ▼
                ┌──────────────────────────────────────────────┐
                │       STREAMING PROTOCOL DISSECTOR           │
                │  - ISAKMP / IKEv1 / IKEv2 Parser             │
                │  - ESP Header & Length Residue Analyzer      │
                │  - AH Header & ICV Extraction                │
                │  - NAT-T Demux & Keepalive Filter            │
                │  - Anti-Replay Sliding Window (RFC 4303)     │
                └──────────────────────┬───────────────────────┘
                                       │
                     ┌─────────────────┴─────────────────┐
                     ▼                                   ▼
        ┌─────────────────────────┐         ┌─────────────────────────┐
        │  CLEARTEXT IKE EXTRACT  │         │   ENCRYPTED ESP PHYSICS │
        │  - Proposals & Xforms   │         │  - Modulo-16 residues   │
        │  - DH Groups & PQC      │         │  - Analytical candidate │
        │  - Leaked ID & VIDs     │         │    feasibility checks   │
        │  - Rekey & Child-SAs    │         │  - Inter-arrival timing │
        └────────────┬────────────┘         └────────────┬────────────┘
                     │                                   │
                     │  ┌────────────────────────────────┘
                     ▼  ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                 FOUR-TIER EVIDENCE ENGINE                   │
        │                                                             │
        │  [Tier 1: Observed]       Direct wire bits (e.g. DH group)  │
        │  [Tier 2: Inferred]       Length physics + ML (e.g. cipher) │
        │  [Tier 3: Not Observable] Out-of-band (e.g. AES key length) │
        │  [Tier 4: Unknown]        Ambiguous / insufficient packets  │
        └──────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
        ┌─────────────────────────────────────────────────────────────┐
        │           STANDARDS COMPLIANCE & RULES ENGINE               │
        │   NIST SP 800-77 Rev. 1 | RFC 8221 | RFC 8247 | RFC 9395   │
        │   66 Automated Checks Across 6 Security Domains             │
        │   (Key Exchange, Encryption, Integrity, Identity, Framing, Ops) │
        └──────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
        ┌─────────────────────────────────────────────────────────────┐
        │                    REPORTING & DASHBOARD                    │
        │  - Letter Grade (A+ to F) & 0-100 Security Score            │
        │  - 5x5 MITRE/CVSS Threat Matrix & Prioritized Remediation   │
        │  - Executive & Technical PDF / JSON / WebUI                 │
        │  - Real-time React Dashboard & REST API                     │
        └─────────────────────────────────────────────────────────────┘
```

---

## 2. Four-Tier Evidence Framework

A core tenet of our design is **intellectual honesty**. Machine learning classifiers should never present inferences as established facts. IPsec X-Ray tags every reported property with one of four evidence tiers:

| Tier | Status | Meaning | Examples |
|---|---|---|---|
| **Tier 1** | `Observed` | Grounded directly in unencrypted wire fields. Zero inference. | IKE version, Initiator/Responder SPI, DH Group ID, PRF, Vendor IDs, plaintext IDs (IKEv1 Aggressive). |
| **Tier 2** | `Inferred` | Derived via packet-length physics, timing distributions, or calibrated Random Forest models. Accompanied by confidence %. | ESP cipher family (AES-GCM vs CBC), Tunnel vs Transport mode, application traffic class (VoIP, interactive, bulk). |
| **Tier 3** | `Not Observable` | Information mathematically destroyed by encryption. Passive sniffing cannot distinguish without decryption. | AES key length (128 vs 256 in CBC), sequence counter extended state (ESN). Handled via recommendations rather than score penalties. |
| **Tier 4** | `Unknown` | Insufficient packets or ambiguous residue distributions. The engine abstains rather than halluncinating. | TFC padding presence in short captures (<10 packets), unobserved Child-SA rekeys. |

---

## 3. Dissector Modular Architecture (`ipsec_xray/protocols/`)

The protocol dissection engine is split into isolated, single-responsibility modules:

- **`isakmp.py`**: Base RFC 2408 message framing, generic attribute decoding (TV/TLV format), `IKEMessage` and `Payload` containers.
- **`ikev1.py`**: ISAKMP Phase 1 (Main Mode, Aggressive Mode) and Phase 2 (Quick Mode) dissectors, transform attribute decoding (RFC 2409).
- **`ikev2.py`**: IKEv2 exchanges (`IKE_SA_INIT`, `IKE_AUTH`, `CREATE_CHILD_SA`, `INFORMATIONAL`), transform negotiation and notification payloads (RFC 7296).
- **`transforms.py`**: IANA registry transform decoders, `Transform` and `Proposal` structured objects.
- **`diffie_hellman.py`**: Classical MODP/ECP groups (Groups 1–32) and Post-Quantum hybrid algorithms (ML-KEM, Kyber, Frodo). Evaluates NIST compliance and classical security bits.
- **`esp.py`**: ESP packet parser (RFC 4303), modulo-residue calculators, framing metrics.
- **`ah.py`**: AH packet parser (RFC 4302), variable ICV length extraction.
- **`nat_t.py`**: Demultiplexer for UDP port 4500; detects RFC 3948 Non-ESP markers (`0x00000000`) and NAT keepalives (`0xFF`).
- **`replay.py`**: RFC 4303 Section 3.4.3 64-packet anti-replay sliding window bitmap. Detects replayed sequence numbers, sequence gaps, and packet reordering.
- **`security_association.py`**: State tracker for parent IKE SAs and negotiated Child-SAs.

---

## 4. Packet-Length Physics & Cipher Infiltration

ESP encapsulates plaintext with the following wire layout:
$$\text{ESP Overhead} = \text{SPI (4B)} + \text{Seq (4B)} + \text{IV (variable)} + \text{Payload} + \text{Pad} + \text{PadLen (1B)} + \text{NextHdr (1B)} + \text{ICV (tag)}$$

Because padding aligns the ciphertext to the cipher block size $B$:
$$\text{PaddedLen} = \lceil (\text{PayloadLen} + 2) / B \rceil \times B$$

Different cipher suites impose distinct overhead signatures:
- **AES-GCM-16**: Block size = 4 bytes (modulo padding), IV = 8 bytes, ICV = 16 bytes. Minimum overhead = $8 + 8 + 0 + 2 + 16 = 34$ bytes.
- **AES-CBC-16 + HMAC-SHA2-256-128**: Block size = 16 bytes, IV = 16 bytes, ICV = 16 bytes. Minimum overhead = $8 + 16 + 0 + 2 + 16 = 42$ bytes.
- **3DES-CBC + HMAC-SHA1-96**: Block size = 8 bytes, IV = 8 bytes, ICV = 12 bytes. Minimum overhead = $8 + 8 + 0 + 2 + 12 = 30$ bytes.

The `physics.py` module evaluates candidate cipher feasibility across all observed packet lengths. The residue distribution modulo 16 acts as an analytical fingerprint, which is fed alongside timing statistics into the machine learning engine.

---

## 5. Calibrated Machine Learning Pipeline

Our inference subsystem employs three distinct models trained on synthetic flows with exact ESP physics:
1. **`cipher_rf.joblib`**: Calibrated Random Forest (100 estimators, 5-fold CV) predicting cipher family and ICV overhead.
2. **`mode_rf.joblib`**: Calibrated classifier distinguishing Transport Mode from Tunnel Mode.
3. **`traffic_rf.joblib`**: Multi-class traffic classifier (VoIP, Interactive SSH/Shell, Bulk Transfer, Mixed).

### Out-of-Distribution (OOD) Protection
To prevent false inferences on atypical captures:
- Prediction probabilities are calibrated via isotonic regression / sigmoid scaling (`CalibratedClassifierCV`).
- If the maximum class probability falls below the confidence threshold ($< 0.55$), the engine **abstains** and marks the field as `Unknown`.

---

## 6. Threat Matrix & Standards Compliance

The compliance engine evaluates 66 automated checks based on:
- **NIST SP 800-77 Rev. 1**: Guide to IPsec VPNs.
- **RFC 8221 / RFC 8247**: Cryptographic Algorithm Implementation Requirements for ESP/AH and IKEv2.
- **RFC 9395**: Deprecation of DES, 3DES, and RC4 in IKE.
- **CNSA 2.0**: Quantum-resistant commercial national security algorithm suite.

Findings are mapped into a 5×5 Risk Matrix (Likelihood vs Impact) with CVSS 3.1 equivalent severity ratings:
- **Critical (Score penalty: -25 to -40)**: Pre-shared key hash leakage (IKEv1 Aggressive), Null encryption, single-DES, export-grade DH.
- **High (Score penalty: -15 to -20)**: 3DES-CBC, MD5/SHA-1 integrity, MODP-1024 (Logjam vulnerable).
- **Medium (Score penalty: -5 to -10)**: Lack of PFS (no Child-SA rekey DH), CBC mode without encrypt-then-MAC, lack of ESN for high-speed flows.
- **Low / Info (Score penalty: 0 to -2)**: Lack of TFC padding, missing quantum-resistant key encapsulation (ML-KEM).

---

## 7. Deployment Topologies

IPsec X-Ray supports multiple deployment targets:
1. **Vercel Serverless**:
   - Packaged as an ASGI app (`api/index.py`).
   - Read-only root filesystem compatible: SQLite databases and scratch directories dynamically map to `/tmp/ipsec_xray_data`.
2. **Edge Sniffer / On-Premise C4I Appliance**:
   - `python -m ipsec_xray.live.sniffer -i eth0`: Real-time packet capture via `scapy` / raw sockets with sliding window state.
3. **Standalone Container / Docker**:
   - Single container exposing REST API on port 8000 and bundled Vite React dashboard on port 80/8000.
