"""ISAKMP (RFC 2408) base header parsing, TLV attribute handling, and message definitions."""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from .transforms import Proposal

IKE_HDR_LEN = 28
IKEV2_FLAG_INITIATOR = 0x08
IKEV2_FLAG_VERSION = 0x10
IKEV2_FLAG_RESPONSE = 0x20
IKEV1_FLAG_ENCRYPTION = 0x01
IKEV1_FLAG_COMMIT = 0x02
IKEV1_FLAG_AUTH_ONLY = 0x04


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
    add_ke: list[tuple[int, int]] = field(default_factory=list)  # (group, len) for additional KE payloads
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


def parse_attrs(buf: bytes, v1: bool = False) -> dict:
    """Decode ISAKMP/IKE attributes (TV or TLV format)."""
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
