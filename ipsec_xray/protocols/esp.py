"""ESP (RFC 4303) and AH (RFC 4302) header extraction and length residue analysis.

Only cleartext fields are available on the wire.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

# Re-export AH dissection for backward compatibility
from .ah import AHHeader, parse_ah


@dataclass
class ESPHeader:
    spi: int
    seq: int
    payload_len: int  # bytes after SPI+Seq (IV + ciphertext + pad + pad_len + next_hdr + ICV)
    total_len: int  # SPI+Seq+payload


def parse_esp(data: bytes) -> Optional[ESPHeader]:
    """Parse ESP header from raw IP or UDP encapsulation payload."""
    if len(data) < 8:
        return None
    spi, seq = struct.unpack("!II", data[:8])
    if spi == 0:
        return None  # SPI 0 is reserved (and is the NAT-T non-ESP marker)
    return ESPHeader(spi, seq, len(data) - 8, len(data))


def esp_length_residue(wire_length: int, block_size: int = 16, tag_size: int = 16) -> int:
    """Calculate the modulo residue of an ESP packet's payload length.

    In ESP framing:
      wire_length = IP_hdr + (UDP_hdr) + 8(ESP_hdr) + IV + ciphertext + pad + 2(pad_len+nxt) + ICV
    Residue modulo block_size isolates differences in IV + ICV overheads, allowing
    AEAD mode identification without decrypting the payload.
    """
    esp_overhead = 8 + tag_size + 2  # SPI+Seq (8), ICV (tag_size), PadLen+NextHdr (2)
    return (wire_length - esp_overhead) % block_size
