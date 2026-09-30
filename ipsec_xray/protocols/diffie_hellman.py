"""Diffie-Hellman group security ratings, key exchange categorization, and PQC mappings."""
from __future__ import annotations

from typing import Optional

from . import registry as R


def dh_security_level(group_id: int) -> dict:
    """Evaluate cryptographic strength and NIST compliance of a DH group ID.

    Returns:
        dict with keys:
          - 'status': 'deprecated', 'legacy', 'acceptable', or 'quantum_resistant'
          - 'rfc_status': RFC 8247 recommendation (e.g., 'MUST NOT', 'SHOULD', etc.)
          - 'security_bits': estimated classical security bits
          - 'name': official IANA name
          - 'quantum_safe': boolean
    """
    info = R.DH_GROUPS.get(group_id)
    if not info:
        return {
            "status": "unknown",
            "rfc_status": "UNKNOWN",
            "security_bits": 0,
            "name": f"DH_GROUP_{group_id}",
            "quantum_safe": False,
        }

    name = info[0]
    rfc_status = info[1] if len(info) > 1 else "UNKNOWN"
    sec_bits = info[2] if len(info) > 2 and isinstance(info[2], (int, float)) else 0

    # PQC hybrid or pure post-quantum algorithms
    is_pqc = "ML-KEM" in name or "Frodo" in name or "Kyber" in name or "PQC" in name

    if is_pqc:
        status = "quantum_resistant"
    elif sec_bits < 112 or group_id in (1, 2, 5) or "MUST NOT" in rfc_status or "SHOULD NOT" in rfc_status:
        status = "deprecated"
    elif sec_bits < 128:
        status = "legacy"
    else:
        status = "acceptable"

    return {
        "status": status,
        "rfc_status": rfc_status,
        "security_bits": sec_bits,
        "name": name,
        "quantum_safe": is_pqc,
    }


def dh_name(group_id: int) -> str:
    """Convenience lookup for DH group names."""
    return R.dh_name(group_id)
