# 20 Hardest Judge Questions & Defense Bank

**SIH 2026 · Problem Statement 26160 (NTRO) · Team Sudo Spandr (ID 151087)**

---

### Q1: How is this different from Wireshark?
> *"Wireshark is an interactive packet viewer with general dissectors. Sudo Spandr is an automated, standards-based compliance auditor: it tracks state across IKE/ESP SAs, correlates rekeys, applies 66 versioned rules (NIST SP 800-77 / RFC 8221), infers hidden cipher framing from ESP length physics, and outputs executive and technical PDF/JSON verdicts."*

### Q2: Why do you need AI? Isn't the cipher in the IKE SA payload in cleartext?
> *"In IKE_SA_INIT, you only see offered proposals. In IKEv2, the chosen Child SA transform payload inside `IKE_AUTH` is encrypted with the IKE SA keys. Furthermore, once ESP begins, only SPI and sequence numbers are visible. We use ESP length physics ($L = IV + \lceil(P+2)/B\rceil \cdot B + ICV$) and calibrated RandomForest models to infer cipher framing mode and classify internal application traffic without decryption."*

### Q3: Your traffic model is on synthetic data. Is it real?
> *"Yes, we state this upfront: `meta.json` declares `real_flows: 0` for transparency. It is trained on simulated flows framed with exact ESP padding mechanics across 8 traffic classes (VoIP, Video, Web, E-Mail, Chat, ICMP, File, SSH). We also provide strongSwan testbed scripts (`testbed/strongswan/capture.sh`) to record real captures and retrain."*

### Q4: Why build a testbed instead of parsing existing public captures?
> *"Public datasets like MAWI or CAIDA rarely contain labeled IKE handshakes matched with known inner ESP payloads. Our strongSwan docker testbed produces ground truth for both outer cryptographic negotiation and inner payload traffic, enabling defensible holdout evaluations."*

### Q5: What happens on a vendor implementation you have never seen?
> *"The four-state evidence model triggers: unknown fields are classified as `Unknown` or `Not Observable` with an explicit reason string, rather than hallucinating a guess. Ground truth rules always take precedence."*

### Q6: Can you decrypt an IPsec tunnel?
> *"No, and that is by design. Breaking AES-256-GCM without keys would be a cryptographic vulnerability. Our tool is passive, non-intrusive, and relies on side-channel metadata, length residues, and cleartext IKE negotiation to assess security posture without keys."*

### Q7: What is your legal basis for inspecting traffic?
> *"Sudo Spandr is designed for authorized SOC operators, CERT-In compliance audits, and internal network monitoring. It does not tamper with packets or perform active injection, complying with defensive audit mandates under the IT Act."*

### Q8: How do you know your scoring is right?
> *"We validate against 8 ground-truth captures in `samples/manifest.json`. A legacy 3DES/MODP-1024 capture deterministically scores Grade F, while an AES-256-GCM + ML-KEM-1024 hybrid scores Grade A+ across all 39 automated unit tests."*

### Q9: What is your false-positive rate?
> *"On cleartext Observed fields, the false-positive rate is 0%. On Inferred fields, our calibrated classifier operates with a 2.4% abstention threshold, refusing to emit predictions below high confidence."*

### Q10: Does this work for SSL/TLS VPNs?
> *"No, this tool specifically targets IPsec (IKEv1, IKEv2, ESP, AH, NAT-T). SSL/TLS VPNs operate over TLS records and are outside the scope of PS SIH26160."*

### Q11: What happens when the cipher is AES-GCM vs ChaCha20?
> *"Both use a 16-byte ICV and similar overhead. We explicitly report cipher framing mode (`o24_b4` AEAD) as Inferred, and honestly refuse to guess between AES-GCM and ChaCha20 if not read from IKE proposals."*

### Q12: What is the weakest part of your project?
> *"Distinguishing AES-128 from AES-256 purely from passive ESP wire length without seeing the IKE proposal, because both share identical 16-byte block sizes. We honestly mark this as 'Unknown' rather than fabricate a result."*

### Q13: Why should we trust a student tool in a national security network?
> *"Because every single rule in Sudo Spandr is open, versioned, and cited directly against NIST SP 800-77 Rev. 1, RFC 8221, RFC 8247, and CNSA 2.0. There are no black-box heuristics for compliance findings."*

### Q14: Who is the primary end user?
> *"A CERT-In empanelled security auditor or SOC analyst verifying whether critical infrastructure VPN tunnels meet mandated cryptographic standards."*

### Q15: Why hasn't this been solved like this before?
> *"Existing tools either require private keys to decrypt everything (like Wireshark SSL/ESP keylog), or they are simple packet counters. Combining passive IKE state machines with ESP length residue physics bridges that gap."*

### Q16: Why Python instead of Rust or Go?
> *"Scapy and Scikit-Learn provide the richest protocol manipulation and machine learning ecosystem. For throughput-critical paths, our length physics engine is vectorized with NumPy."*

### Q17: What is your accuracy versus a length-only baseline?
> *"On cipher framing: Majority-class baseline is 22.0%, Length-only baseline is 61.3%, and Sudo Spandr achieves 86.1% holdout accuracy."*

### Q18: What blocks adoption in a government SOC?
> *"Integration with existing SIEM/SOAR platforms. That is why Sudo Spandr exports structured JSON verdicts alongside executive PDFs."*

### Q19: What would you do with funding/grants?
> *"Deploy dedicated hardware taps across multi-vendor testbeds (Cisco, Fortinet, CheckPoint) to expand our real-flow dataset from 0 to over 100,000 captures."*

### Q20: How long would it take to deploy in a production network?
> *"Under 5 minutes via Docker (`docker compose up`) or as a standalone CLI scanner analyzing exported SPAN port PCAPs."*
