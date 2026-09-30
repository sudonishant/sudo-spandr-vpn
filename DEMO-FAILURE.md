# DEMO-FAILURE Plan: In-Flight Contingency Guide

**Problem Statement SIH26160 (NTRO) · Team Sudo Spandr (ID 151087)**

---

## 1. What to do if the Live Web UI Fails on Stage
1. **Switch Instantly to Local Server**:
   ```bash
   ./run.sh
   # Opens immediately on http://localhost:8000
   ```
2. **Switch to CLI Terminal Mode (Zero UI Dependency)**:
   ```bash
   # Analyze legacy 3DES capture in 1.8 seconds:
   python3 -m ipsec_xray.cli analyze samples/legacy_ikev1_aggressive_3des.pcap --profile government

   # Analyze modern PQC capture:
   python3 -m ipsec_xray.cli analyze samples/good_ikev2_gcm_pqc_pfs.pcap --profile government
   ```
3. **If Projector / Network Dies**:
   - Pre-generated PDF reports exist in `data/` and `docs/`.
   - Hand the printed 1-page executive summary directly to the judges.

## 2. Recovery Phrase for Presenter
> *"While the cloud edge reconnects, let me show you the offline CLI engine analyzing the exact same strongSwan capture locally in under two seconds."*
