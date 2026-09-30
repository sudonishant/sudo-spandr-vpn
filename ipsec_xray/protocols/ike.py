"""Stand-alone IKEv1 (ISAKMP, RFC 2408/2409) and IKEv2 (RFC 7296) header + payload parser.

Only the cleartext structure is parsed; encrypted payloads (IKEv1 E-bit messages, IKEv2 SK/SKF)
are recorded by size, which is exactly the information a passive analyzer can use.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from . import registry as R
from .diffie_hellman import dh_name, dh_security_level
from .ikev1 import decode_v1_attrs, parse_v1_sa, v1_id_type
from .ikev2 import parse_v2_sa, v2_id_type
from .isakmp import (
    IKE_HDR_LEN,
    IKEV1_FLAG_AUTH_ONLY,
    IKEV1_FLAG_COMMIT,
    IKEV1_FLAG_ENCRYPTION,
    IKEV2_FLAG_INITIATOR,
    IKEV2_FLAG_RESPONSE,
    IKEV2_FLAG_VERSION,
    IKEMessage,
    Payload,
    parse_attrs,
)
from .transforms import Proposal, Transform, v2_transform_name

# Aliases for backwards compatibility
_v2_transform_name = v2_transform_name
_parse_attrs = parse_attrs
_decode_v1_attrs = decode_v1_attrs
_parse_v2_sa = parse_v2_sa
_parse_v1_sa = parse_v1_sa
_v1_id_type = v1_id_type
_v2_id_type = v2_id_type


def _id_value(t: int, raw: bytes) -> str:
    """Extract human-readable representation of ID payload."""
    try:
        if t == 1 and len(raw) == 4:
            return ".".join(str(b) for b in raw)
        if t in (2, 3) and raw:
            return raw.decode("ascii", "replace")
        if t == 5 and len(raw) == 16:
            return ":".join(raw[i:i + 2].hex() for i in range(0, 16, 2))
        if t == 11:
            try:
                return raw.decode("ascii")
            except UnicodeDecodeError:
                return raw.hex()
    except Exception:  # pragma: no cover
        pass
    return raw[:32].hex()


def vendor_label(vid_hex: str) -> str:
    """Match vendor ID payload hex hash against known IPsec implementation hashes."""
    for prefix, name in R.VENDOR_IDS.items():
        if vid_hex.startswith(prefix):
            return name
    return "unknown vendor id"


def _decode_payload(msg: IKEMessage, pl: Payload, v1: bool) -> None:
    t, d = pl.ptype, pl.data
    if v1:
        if t == 1:  # SA
            msg.proposals.extend(_parse_v1_sa(d, msg))
        elif t == 4:  # KE
            msg.ke_len = len(d)
        elif t == 10:  # NONCE
            msg.nonce_len = len(d)
        elif t == 5 and len(d) >= 4:  # ID (plaintext in aggressive mode / phase 1 msg 5-6 are encrypted)
            idt = d[0]
            msg.ids.append({
                "type": idt,
                "type_name": _v1_id_type(idt),
                "len": len(d) - 4,
                "value": _id_value(idt, d[4:]),
            })
            pl.info = msg.ids[-1]
        elif t == 11 and len(d) >= 8:  # Notify
            ntype = struct.unpack("!H", d[6:8])[0]
            msg.notifies.append({"type": ntype, "name": f"V1_NOTIFY_{ntype}", "len": len(d)})
        elif t == 13:  # Vendor ID
            msg.vendor_ids.append(d.hex())
        elif t in (8, 9):  # HASH / SIG in cleartext (aggressive mode message 2/3)
            msg.hash_or_sig_plain = True
        elif t == 6:
            msg.cert_len += len(d)
        elif t == 7:
            msg.certreq = True
        return

    # ---- IKEv2
    if t == 33:
        msg.proposals.extend(_parse_v2_sa(d, msg))
    elif t == 34 and len(d) >= 4:
        grp = struct.unpack("!H", d[:2])[0]
        if msg.ke_group is None:
            msg.ke_group, msg.ke_len = grp, len(d) - 4
        else:
            msg.add_ke.append((grp, len(d) - 4))
        pl.info = {"group": grp, "group_name": R.dh_name(grp), "len": len(d) - 4}
    elif t == 40:
        msg.nonce_len = len(d)
    elif t == 41 and len(d) >= 4:
        proto, spisz, ntype = struct.unpack("!BBH", d[:4])
        n = {
            "type": ntype,
            "name": R.IKEV2_NOTIFY.get(ntype, f"NOTIFY_{ntype}"),
            "protocol": proto,
            "spi": d[4:4 + spisz].hex(),
            "len": len(d) - 4 - spisz,
            "data": d[4 + spisz:4 + spisz + 64].hex(),
        }
        msg.notifies.append(n)
        pl.info = n
    elif t == 43:
        msg.vendor_ids.append(d.hex())
    elif t in (35, 36) and len(d) >= 4:
        idt = d[0]
        info = {
            "type": idt,
            "type_name": _v2_id_type(idt),
            "len": len(d) - 4,
            "value": _id_value(idt, d[4:]),
            "role": "IDi" if t == 35 else "IDr",
        }
        msg.ids.append(info)
        pl.info = info
    elif t in (46, 53):
        msg.sk_len += len(d)
    elif t == 37:
        msg.cert_len += len(d)
    elif t == 38:
        msg.certreq = True


def parse_ike(data: bytes) -> Optional[IKEMessage]:
    """Parse one IKE/ISAKMP message (UDP payload without the NAT-T non-ESP marker). Returns None if not IKE."""
    if len(data) < IKE_HDR_LEN:
        return None
    spi_i, spi_r, nxt, ver, exch, flags, msg_id, length = struct.unpack("!8s8sBBBBII", data[:IKE_HDR_LEN])
    major = ver >> 4
    if major not in (1, 2):
        return None
    if length < IKE_HDR_LEN or length > 65535:
        return None
    v1 = major == 1
    if v1:
        ename = R.IKEV1_EXCHANGES.get(exch, f"EXCH_{exch}")
        initiator = spi_r == b"\x00" * 8 or True  # IKEv1 has no initiator flag; caller decides by SPI ordering
        response = False
        encrypted = bool(flags & IKEV1_FLAG_ENCRYPTION)
    else:
        ename = R.IKEV2_EXCHANGES.get(exch, f"EXCH_{exch}")
        initiator = bool(flags & IKEV2_FLAG_INITIATOR)
        response = bool(flags & IKEV2_FLAG_RESPONSE)
        encrypted = False
    msg = IKEMessage(major, spi_i.hex(), spi_r.hex(), exch, ename, flags, msg_id, length, initiator, response, encrypted)
    if len(data) < length:
        msg.truncated = True
    body = data[IKE_HDR_LEN:length]
    names = R.IKEV1_PAYLOADS if v1 else R.IKEV2_PAYLOADS

    if v1 and encrypted:
        msg.sk_len = len(body)
        msg.payloads.append(Payload(0, "ENCRYPTED", len(body)))
        return msg

    i = 0
    ptype = nxt
    guard = 0
    declared = length - IKE_HDR_LEN
    while ptype != 0 and i + 4 <= len(body) and guard < 64:
        guard += 1
        pnext, crit, plen = struct.unpack("!BBH", body[i:i + 4])
        if plen < 4 or i + plen > declared:
            msg.errors.append(f"payload {ptype} length {plen} out of range")
            break
        if i + plen > len(body):
            # capture was truncated (snaplen) - not a protocol error
            msg.truncated = True
            pl = Payload(ptype, names.get(ptype, f"P{ptype}"), plen, body[i + 4:])
            if ptype in (46, 53):
                msg.sk_len += plen - 4
            msg.payloads.append(pl)
            break
        pdata = body[i + 4:i + plen]
        pl = Payload(ptype, names.get(ptype, f"P{ptype}"), plen, pdata)
        _decode_payload(msg, pl, v1)
        msg.payloads.append(pl)
        i += plen
        ptype = pnext
    return msg
