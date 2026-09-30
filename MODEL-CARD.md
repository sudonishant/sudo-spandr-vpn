# Model Card: IPsec X-Ray Passive Traffic & Cipher Inference Models

**Problem Statement SIH26160 (NTRO) · Team Sudo Spandr (ID 151087)**

---

## 1. Model Details

- **Model Architecture**: Ensemble Random Forest Classifiers with Calibrated Probability Estimates.
- **Trained Models**:
  1. `traffic_rf.joblib`: 37 features, 8 traffic classes (VoIP, Video, Web, E-Mail, Chat, ICMP, File, SSH).
  2. `cipher_rf.joblib`: 36 features, predicts block size & ICV framing residue (`o24_b4`, `o32_b16`, etc.).
  3. `mode_rf.joblib`: 59 features, classifies Tunnel vs Transport mode.
- **Library**: `scikit-learn >= 1.4.0`, serialized via `joblib`.

## 2. Quantitative Performance & Baselines

| Model | Majority Baseline | Length-Only Baseline | IPsec X-Ray (Holdout) | Macro F1-Score | Abstention Rate |
|---|---|---|---|---|---|
| **Traffic Classifier** | 12.5% | 48.6% | **100.0%** (Synthetic) | 1.000 | 2.4% |
| **Cipher Framing** | 22.0% | 61.3% | **86.1%** | 0.842 | 3.1% |
| **Mode Classifier** | 50.0% | 72.1% | **95.7%** | 0.941 | 1.8% |

*(Note: Ground truth training flows count = 1,760 flows; 220 per class. Real strongSwan lab flows = 0 in current v1 release, flagged transparently in `models/meta.json`)*.

## 3. Four-Tier Evidence Framework

Every output in IPsec X-Ray strictly conforms to one of four evidence states:
1. **Observed (Cleartext Wire)**: Extracted directly from IKEv1/IKEv2 SA, KE, TS, or Notify payloads.
2. **Inferred (Side-Channel Physics & ML)**: Derived from ESP length residue, packet timing variance, and burstiness with an associated confidence metric.
3. **Not Observable (Cryptographic Limit)**: Fields physically impossible to distinguish on the wire (e.g. AES-128 vs AES-256).
4. **Unknown (Information Absent)**: Parameters requiring unseen wire events (e.g. PFS status when no rekey occurred during the capture window).

## 4. Ethical Use & Out-of-Scope Deployments

- **Intended Use**: Authorized defensive network audits, CERT-In compliance verification, and critical infrastructure assessment.
- **Out of Scope**: Real-time offensive interception or unauthorized eavesdropping. The tool performs zero active packet injection and zero decryption.
