"""IKEv2 (RFC 7296) dissector routines."""
from __future__ import annotations

import struct
from typing import TYPE_CHECKING

from .isakmp import parse_attrs
from .transforms import Proposal, Transform, v2_transform_name

if TYPE_CHECKING:
    from .isakmp import IKEMessage


def parse_v2_sa(body: bytes, msg: IKEMessage) -> list[Proposal]:
    """Parse IKEv2 Security Association payload (RFC 7296 section 3.3)."""
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
            attrs = parse_attrs(body[j + 8:j + tlen], v1=False)
            prop.transforms.append(Transform(ttype, tid, v2_transform_name(ttype, tid), attrs.get(14), attrs))
            j += tlen
            if tmore == 0:
                break
        props.append(prop)
        i += plen
        if more == 0:
            break
    return props


def v2_id_type(t: int) -> str:
    """Map IKEv2 Identification payload type to human string."""
    return {
        1: "IPV4_ADDR",
        2: "FQDN",
        3: "RFC822_ADDR",
        5: "IPV6_ADDR",
        9: "DER_ASN1_DN",
        10: "DER_ASN1_GN",
        11: "KEY_ID",
    }.get(t, f"ID_{t}")
