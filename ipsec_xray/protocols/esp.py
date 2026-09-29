"""ESP (RFC 4303) and AH (RFC 4302) header extraction. Only cleartext fields are available on the wire."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class ESPHeader:
    spi: int
    seq: int
    payload_len: int        # bytes after SPI+Seq (IV + ciphertext + pad + ICV)
    total_len: int          # SPI+Seq+payload


@dataclass
class AHHeader:
    next_header: int
    spi: int
    seq: int
    icv_len: int
    total_len: int


def parse_esp(data: bytes) -> Optional[ESPHeader]:
    if len(data) < 8:
        return None
    spi, seq = struct.unpack("!II", data[:8])
    if spi == 0:
        return None     # SPI 0 is reserved (and is the NAT-T non-ESP marker)
    return ESPHeader(spi, seq, len(data) - 8, len(data))


def parse_ah(data: bytes) -> Optional[AHHeader]:
    if len(data) < 12:
        return None
    nh, plen, _res, spi, seq = struct.unpack("!BBHII", data[:12])
    icv_len = (plen + 2) * 4 - 12
    return AHHeader(nh, spi, seq, max(0, icv_len), (plen + 2) * 4)
