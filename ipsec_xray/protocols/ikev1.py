"""IKEv1 (ISAKMP RFC 2408, IKE RFC 2409) dissector routines."""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from . import registry as R
from .isakmp import parse_attrs
from .transforms import Proposal, Transform

if TYPE_CHECKING:
    from .isakmp import IKEMessage


def decode_v1_attrs(a: dict) -> dict:
    """Decode IKEv1 ISAKMP SA proposal attributes."""
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


def parse_v1_sa(body: bytes, msg: IKEMessage) -> list[Proposal]:
    """Parse IKEv1 Security Association payload (RFC 2408 section 3.4)."""
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
            attrs = parse_attrs(body[j + 8:j + tlen], v1=True)
            dec = decode_v1_attrs(attrs)
            # Represent as pseudo-transforms so the rest of the pipeline is version agnostic
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


def v1_id_type(t: int) -> str:
    """Map IKEv1 Identification payload type to human string."""
    return {
        1: "IPV4_ADDR",
        2: "FQDN",
        3: "USER_FQDN",
        4: "IPV4_ADDR_SUBNET",
        5: "IPV6_ADDR",
        6: "IPV6_ADDR_SUBNET",
        7: "IPV4_ADDR_RANGE",
        8: "IPV6_ADDR_RANGE",
        9: "DER_ASN1_DN",
        10: "DER_ASN1_GN",
        11: "KEY_ID",
    }.get(t, f"ID_{t}")
