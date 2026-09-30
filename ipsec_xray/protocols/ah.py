"""Authentication Header (AH, RFC 4302) dissector."""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class AHHeader:
    next_header: int
    spi: int
    seq: int
    icv_len: int
    total_len: int


def parse_ah(data: bytes) -> Optional[AHHeader]:
    """Parse AH header from raw IP payload. Returns None if truncated or invalid."""
    if len(data) < 12:
        return None
    nh, plen, _res, spi, seq = struct.unpack("!BBHII", data[:12])
    icv_len = (plen + 2) * 4 - 12
    return AHHeader(nh, spi, seq, max(0, icv_len), (plen + 2) * 4)
