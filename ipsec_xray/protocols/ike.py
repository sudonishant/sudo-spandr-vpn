"""Stand-alone IKEv1 (ISAKMP, RFC 2408/2409) and IKEv2 (RFC 7296) header + payload parser.

Only the cleartext structure is parsed; encrypted payloads (IKEv1 E-bit messages, IKEv2 SK/SKF) are recorded by size,
which is exactly the information a passive analyzer can use.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from . import registry as R

IKE_HDR_LEN = 28
IKEV2_FLAG_INITIATOR = 0x08
IKEV2_FLAG_VERSION = 0x10
IKEV2_FLAG_RESPONSE = 0x20
IKEV1_FLAG_ENCRYPTION = 0x01
IKEV1_FLAG_COMMIT = 0x02
IKEV1_FLAG_AUTH_ONLY = 0x04


@dataclass
class Transform:
    ttype: int
    tid: int
    name: str
    keylen: Optional[int] = None
    attrs: dict = field(default_factory=dict)

    @property
    def ttype_name(self) -> str:
        return R.IKEV2_TRANSFORM_TYPES.get(self.ttype, f"T{self.ttype}")

    def label(self) -> str:
        return f"{self.name}-{self.keylen}" if self.keylen else self.name


@dataclass
class Proposal:
    number: int
    protocol: int            # 1 IKE, 2 AH, 3 ESP
    spi: bytes
    transforms: list[Transform] = field(default_factory=list)
    v1_attrs: dict = field(default_factory=dict)   # IKEv1 phase-1 preferred transform attributes (decoded)
    v1_transforms: list = field(default_factory=list)   # all IKEv1 transforms (decoded attribute dicts)

    @property
    def protocol_name(self) -> str:
        return {1: "IKE", 2: "AH", 3: "ESP"}.get(self.protocol, f"P{self.protocol}")

    def by_type(self, ttype: int) -> list[Transform]:
        return [t for t in self.transforms if t.ttype == ttype]

    def summary(self) -> str:
        parts = []
        for tt in (1, 2, 3, 4, 6, 5):
            names = [t.label() for t in self.by_type(tt)]
            if names:
                parts.append(f"{R.IKEV2_TRANSFORM_TYPES.get(tt, tt)}={'/'.join(names)}")
        if self.v1_transforms:
            parts = [" | ".join(", ".join(f"{k}={v}" for k, v in t.items()) for t in self.v1_transforms)]
        return f"{self.protocol_name}#{self.number}: " + " ".join(parts)


@dataclass
class Payload:
    ptype: int
    name: str
    length: int
    data: bytes = b""
    info: dict = field(default_factory=dict)


@dataclass
class IKEMessage:
    version: int
    spi_i: str
    spi_r: str
    exchange: int
    exchange_name: str
    flags: int
    msg_id: int
    length: int
    initiator: bool
    response: bool
    encrypted: bool
    payloads: list[Payload] = field(default_factory=list)
    proposals: list[Proposal] = field(default_factory=list)
    ke_group: Optional[int] = None
    ke_len: Optional[int] = None
    add_ke: list[tuple[int, int]] = field(default_factory=list)   # (group, len) for additional KE payloads
    nonce_len: Optional[int] = None
    notifies: list[dict] = field(default_factory=list)
    vendor_ids: list[str] = field(default_factory=list)
    ids: list[dict] = field(default_factory=list)
    sk_len: int = 0
    cert_len: int = 0
    certreq: bool = False
    hash_or_sig_plain: bool = False
    truncated: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def payload_names(self) -> list[str]:
        return [p.name for p in self.payloads]

    def notify_names(self) -> list[str]:
        return [n["name"] for n in self.notifies]


# --------------------------------------------------------------------------- helpers
def _v2_transform_name(ttype: int, tid: int) -> str:
    if ttype == 1:
        return R.IKEV2_ENCR.get(tid, (f"ENCR_{tid}",))[0]
    if ttype == 2:
        return R.IKEV2_PRF.get(tid, (f"PRF_{tid}",))[0]
    if ttype == 3:
        return R.IKEV2_INTEG.get(tid, (f"INTEG_{tid}",))[0]
    if ttype == 4 or 6 <= ttype <= 12:
        return R.DH_GROUPS.get(tid, (f"DH_{tid}",))[0]
    if ttype == 5:
        return {0: "NO_ESN", 1: "ESN"}.get(tid, f"ESN_{tid}")
    return f"T{ttype}_{tid}"


def _parse_attrs(buf: bytes, v1: bool) -> dict:
    """Decode ISAKMP/IKE attributes (TV or TLV)."""
    out: dict = {}
    i = 0
    while i + 4 <= len(buf):
        atype, = struct.unpack("!H", buf[i:i + 2])
        af = atype & 0x8000
        atype &= 0x7FFF
        if af:
            val = struct.unpack("!H", buf[i + 2:i + 4])[0]
            i += 4
        else:
            ln = struct.unpack("!H", buf[i + 2:i + 4])[0]
            raw = buf[i + 4:i + 4 + ln]
            val = int.from_bytes(raw, "big") if 0 < len(raw) <= 8 else raw.hex()
            i += 4 + ln
        out[atype] = val
    return out


def _decode_v1_attrs(a: dict) -> dict:
    d = {}
    if 1 in a:
        d["ENCR"] = R.IKEV1_ENCR.get(a[1], (f"ENCR_{a[1]}",))[0]
    if 14 in a:
        d["KEY_LENGTH"] = a[14]
    if 2 in a:
        d["HASH"] = R.IKEV1_HASH.get(a[2], (f"HASH_{a[2]}",))[0]
    if 3 in a:
        d["AUTH"] = R.IKEV1_AUTH.get(a[3], f"AUTH_{a[3]}")
    if 4 in a:
        d["GROUP"] = a[4]
    if 11 in a:
        d["LIFE_TYPE"] = {1: "seconds", 2: "kilobytes"}.get(a[11], a[11])
    if 12 in a:
        d["LIFE_DURATION"] = a[12]
    return d


def _parse_v2_sa(body: bytes, msg: IKEMessage) -> list[Proposal]:
    props: list[Proposal] = []
    i = 0
    while i + 8 <= len(body):
        more, _, plen, pnum, proto, spisz, ntrans = struct.unpack("!BBHBBBB", body[i:i + 8])
        if plen < 8 or i + plen > len(body):
            msg.errors.append("SA proposal length out of range")
            break
        spi = body[i + 8:i + 8 + spisz]
        j = i + 8 + spisz
        prop = Proposal(pnum, proto, spi)
        end = i + plen
        while j + 8 <= end:
            tmore, _, tlen, ttype, _, tid = struct.unpack("!BBHBBH", body[j:j + 8])
            if tlen < 8 or j + tlen > end:
                msg.errors.append("transform length out of range")
                break
            attrs = _parse_attrs(body[j + 8:j + tlen], v1=False)
            prop.transforms.append(Transform(ttype, tid, _v2_transform_name(ttype, tid), attrs.get(14), attrs))
            j += tlen
            if tmore == 0:
                break
        props.append(prop)
        i += plen
        if more == 0:
            break
    return props


def _parse_v1_sa(body: bytes, msg: IKEMessage) -> list[Proposal]:
    props: list[Proposal] = []
    if len(body) < 8:
        return props
    doi, situation = struct.unpack("!II", body[:8])
    i = 8
    while i + 8 <= len(body):
        nxt, _, plen, pnum, proto, spisz, ntrans = struct.unpack("!BBHBBBB", body[i:i + 8])
        if plen < 8 or i + plen > len(body):
            msg.errors.append("v1 proposal length out of range")
            break
        spi = body[i + 8:i + 8 + spisz]
        j = i + 8 + spisz
        end = i + plen
        prop = Proposal(pnum, proto, spi)
        while j + 8 <= end:
            tnxt, _, tlen, tnum, tid, _ = struct.unpack("!BBHBBH", body[j:j + 8])
            if tlen < 8 or j + tlen > end:
                msg.errors.append("v1 transform length out of range")
                break
            attrs = _parse_attrs(body[j + 8:j + tlen], v1=True)
            dec = _decode_v1_attrs(attrs)
            # represent as pseudo-transforms so the rest of the pipeline is version agnostic
            t = Transform(1, tid, dec.get("ENCR", f"KEY_IKE_{tid}"), dec.get("KEY_LENGTH"), attrs)
            prop.transforms.append(t)
            if "HASH" in dec:
                prop.transforms.append(Transform(2, attrs.get(2, 0), "HMAC_" + dec["HASH"], None, {}))
            if "GROUP" in dec:
                prop.transforms.append(Transform(4, dec["GROUP"], R.DH_GROUPS.get(dec["GROUP"], (f"DH_{dec['GROUP']}",))[0]))
            if not prop.v1_attrs:
                prop.v1_attrs = dec
            prop.v1_transforms.append(dec)
            j += tlen
            if tnxt == 0:
                break
        props.append(prop)
        i += plen
        if nxt == 0:
            break
    return props


# --------------------------------------------------------------------------- main entry
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


def _decode_payload(msg: IKEMessage, pl: Payload, v1: bool) -> None:
    t, d = pl.ptype, pl.data
    if v1:
        if t == 1:      # SA
            msg.proposals.extend(_parse_v1_sa(d, msg))
        elif t == 4:    # KE
            msg.ke_len = len(d)
        elif t == 10:   # NONCE
            msg.nonce_len = len(d)
        elif t == 5 and len(d) >= 4:    # ID (plaintext in aggressive mode / phase 1 msg 5-6 are encrypted)
            idt = d[0]
            msg.ids.append({"type": idt, "type_name": _v1_id_type(idt), "len": len(d) - 4,
                            "value": _id_value(idt, d[4:])})
            pl.info = msg.ids[-1]
        elif t == 11 and len(d) >= 8:   # Notify
            ntype = struct.unpack("!H", d[6:8])[0]
            msg.notifies.append({"type": ntype, "name": f"V1_NOTIFY_{ntype}", "len": len(d)})
        elif t == 13:   # Vendor ID
            msg.vendor_ids.append(d.hex())
        elif t in (8, 9):   # HASH / SIG in cleartext (aggressive mode message 2/3)
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
        n = {"type": ntype, "name": R.IKEV2_NOTIFY.get(ntype, f"NOTIFY_{ntype}"), "protocol": proto,
             "spi": d[4:4 + spisz].hex(), "len": len(d) - 4 - spisz, "data": d[4 + spisz:4 + spisz + 64].hex()}
        msg.notifies.append(n)
        pl.info = n
    elif t == 43:
        msg.vendor_ids.append(d.hex())
    elif t in (35, 36) and len(d) >= 4:
        idt = d[0]
        info = {"type": idt, "type_name": _v2_id_type(idt), "len": len(d) - 4, "value": _id_value(idt, d[4:]),
                "role": "IDi" if t == 35 else "IDr"}
        msg.ids.append(info)
        pl.info = info
    elif t in (46, 53):
        msg.sk_len += len(d)
    elif t == 37:
        msg.cert_len += len(d)
    elif t == 38:
        msg.certreq = True


def _v2_id_type(t: int) -> str:
    return {1: "IPV4_ADDR", 2: "FQDN", 3: "RFC822_ADDR", 5: "IPV6_ADDR", 9: "DER_ASN1_DN", 10: "DER_ASN1_GN", 11: "KEY_ID"}.get(t, f"ID_{t}")


def _v1_id_type(t: int) -> str:
    return {1: "IPV4_ADDR", 2: "FQDN", 3: "USER_FQDN", 4: "IPV4_ADDR_SUBNET", 5: "IPV6_ADDR", 6: "IPV6_ADDR_SUBNET",
            7: "IPV4_ADDR_RANGE", 8: "IPV6_ADDR_RANGE", 9: "DER_ASN1_DN", 10: "DER_ASN1_GN", 11: "KEY_ID"}.get(t, f"ID_{t}")


def _id_value(t: int, raw: bytes) -> str:
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
    for prefix, name in R.VENDOR_IDS.items():
        if vid_hex.startswith(prefix):
            return name
    return "unknown vendor id"
