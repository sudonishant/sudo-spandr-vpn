"""NAT Traversal (RFC 3947, RFC 3948) dissector and encapsulation helper."""
from __future__ import annotations

NON_ESP_MARKER = b"\x00\x00\x00\x00"
NAT_KEEPALIVE_BYTE = b"\xff"


def is_nat_keepalive(payload: bytes) -> bool:
    """Check if UDP payload is an unencrypted RFC 3948 NAT keepalive packet."""
    return payload == NAT_KEEPALIVE_BYTE or payload == b"\xff\xff" or payload == b"\x00"


def has_non_esp_marker(payload: bytes) -> bool:
    """Detect whether UDP port 4500 payload starts with the 4-byte 0x00000000 Non-ESP Marker (RFC 3948)."""
    return len(payload) >= 4 and payload[:4] == NON_ESP_MARKER


def strip_non_esp_marker(payload: bytes) -> bytes:
    """Strip 4-byte Non-ESP marker to yield raw ISAKMP/IKE message."""
    if has_non_esp_marker(payload):
        return payload[4:]
    return payload
