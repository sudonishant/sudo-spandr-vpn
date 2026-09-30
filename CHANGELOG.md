# Changelog

All notable changes to the **IPsec X-Ray** project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.0] - 2026-09-30

### Added
- **Modular Protocol Dissectors**:
  - Split monolithic IKE dissector into dedicated modules: `isakmp.py`, `ikev1.py`, `ikev2.py`, `transforms.py`, `diffie_hellman.py`, `esp.py`, `ah.py`, `nat_t.py`, `replay.py`, and `security_association.py`.
  - Re-exported full public API in `ipsec_xray.protocols.__init__.py` for 100% backward compatibility.
- **Anti-Replay Window Tracker**:
  - Implemented RFC 4303 Section 3.4.3 sliding window with bitmap checks for packet freshness, replay attack detection, and sequence gap quantification.
- **Feature Importance Extractor**:
  - Added `ipsec_xray.analysis.importance` providing MDI (Mean Decrease in Impurity) feature importances for CalibratedClassifierCV Random Forest ensembles.
- **Protocol Test Suite**:
  - Added `tests/test_protocols_modular.py` bringing total passing test suite to 44 tests.
- **UI Accessibility (WCAG 2.1 AA)**:
  - Added global `:focus-visible` ring indicators, `.sr-only` utility classes, and `@media (prefers-reduced-motion)` overrides.
  - Implemented semantic ARIA landmarks (`<header role="banner">`, `<main id="main">`, `<footer role="contentinfo">`, `aria-current="page"`, `aria-live="polite"`).
  - Integrated one-click scenario runner buttons for instant judge demonstrations ("Try Legacy Grade F", "Try Modern PQC Grade A").
- **Engineering Documentation**:
  - Published comprehensive `ARCHITECTURE.md` detailing mathematical packet length physics, four-tier evidence framework, and serverless edge deployment.

---

## [1.0.0] - 2026-09-29

### Added
- **Core Passive IPsec Engine**:
  - Zero-decryption, zero-key analysis of IKEv1, IKEv2, ESP, AH, and NAT-T traffic.
  - Packet-length physics engine for AEAD vs CBC cipher framing separation without decryption.
  - Calibrated Random Forest models for ESP cipher suite, encapsulation mode, and traffic profiling.
  - 66 automated compliance checks across NIST SP 800-77 Rev. 1, RFC 8221, RFC 8247, RFC 9395, and CNSA 2.0.
  - Four assessment profiles: Baseline, Strict, Post-Quantum, and Legacy.
- **Vercel Serverless Integration**:
  - Configured `api/index.py` ASGI handler with dynamic `/tmp` scratch paths for SQLite and model caches.
  - Live `/healthz` and `/api/v1/health` status endpoints.
- **Interactive Web Dashboard**:
  - React + Vite single-page application with real-time packet inspection, timing charts, threat matrix, and PDF export.
- **Open Source Packaging**:
  - Added Apache-2.0 `LICENSE`, `pyproject.toml`, `Makefile`, `.pre-commit-config.yaml`, and `CONTRIBUTING.md`.
  - Published `DATASET-CARD.md` and `MODEL-CARD.md` documenting transparent training methodologies and honest metric disclosures.
