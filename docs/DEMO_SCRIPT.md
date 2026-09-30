# 90-Second Demo Script: Sudo Spandr (SIH 2026 / PS-26160)

**Presenter**: [Presenter Name]  
**Technical Operator**: [Operator Name]  
**Target Duration**: 90 Seconds  

---

### [00:00 - 00:15] The Hook & The Problem
> *"Judges, 90% of cryptographic decisions for an IPsec tunnel are negotiated in cleartext before the first encrypted byte travels. Nobody inspects that stream until a breach happens. Our framework, Sudo Spandr, parses the IKE handshake, infers hidden ESP cipher parameters through packet-length physics, and benchmarks compliance without keys or decryption."*

### [00:15 - 00:45] Action 1: Uploading Legacy Capture (Sweet32 / Logjam)
1. **Operator clicks**: Preloaded Scenario -> `legacy_ikev1_aggressive_3des.pcap`.
2. **Presenter speaks**:
> *"Notice packet 1: IKEv1 Aggressive Mode offering 3DES and MODP-1024. Our engine immediately fires Rule CHK-IKE-01 and flags Sweet32 risk. In under two seconds, the tunnel receives Grade F with five prioritized remediations."*

### [00:45 - 01:15] Action 2: Uploading Modern PQC Capture (ML-KEM-1024)
1. **Operator clicks**: Preloaded Scenario -> `good_ikev2_gcm_pqc_pfs.pcap`.
2. **Presenter speaks**:
> *"Now we analyze a modern defense tunnel. Here, IKEv2 negotiates AES-256-GCM with post-quantum ML-KEM-1024 hybrid key exchange and Perfect Forward Secrecy. Grade A+ with full CNSA 2.0 readiness."*

### [01:15 - 01:30] Action 3: The Honesty Anchor (The Unknown State)
1. **Operator points to**: Evidence Tier Chips (`Observed`, `Inferred`, `Unknown`).
2. **Presenter concludes**:
> *"Unlike black-box scanners that guess, we never fabricate. When a capture lacks rekeys, PFS is honestly reported as 'Unknown' rather than a guess. That is defensible cybersecurity for national critical infrastructure."*
