# Contributing to IPsec X-Ray (Team Sudo Spandr)

Thank you for contributing to IPsec X-Ray, an AI-powered IPsec protocol analyzer developed for Smart India Hackathon (SIH 2026, Problem Statement SIH26160 / NTRO).

---

## 1. How to Add a New Compliance Check

1. Open `ipsec_xray/assessment/checks.yaml`.
2. Append a new check definition with strict adherence to the schema:
   ```yaml
   - id: CHK-CUSTOM-01
     domain: conf        # ke | conf | integ | fs | replay | meta | hyg
     title: Human-readable check title
     rfc: RFC XXXX Section Y.Z
     severity: critical   # critical | high | medium | low | info
     expr: <python-safe-expression-evaluating-session-facts>
     fix: Actionable, vendor-neutral remediation sentence.
     threats: [TH-01]     # Map to threat IDs in threats.yaml
   ```
3. Run `pytest tests/test_engine_api_report.py` to ensure all checks validate properly.

## 2. How to Add a New Testbed Scenario PCAP

1. Place the generated `.pcap` in `samples/`.
2. Register the ground truth in `samples/manifest.json`:
   ```json
   "my_new_scenario": {
     "ike_version": 2,
     "ike": "AES_GCM_16-256 / ECP-384",
     "esp": "AES-GCM-16 (AEAD)",
     "mode": "tunnel",
     "traffic": "web",
     "pfs": "on",
     "ipver": 4,
     "expected_grade": ["A"],
     "description": "Scenario description",
     "file": "my_new_scenario.pcap"
   }
   ```
3. Verify with `pytest tests/test_inference.py`.

## 3. Pull Request Guidelines

- Ensure `make test` passes with zero failures.
- Adhere to the four-tier evidence convention: never emit a fabricated value. Use `Unknown` or `Not Observable` when evidence is physically absent on the wire.
