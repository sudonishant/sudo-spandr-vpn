"""Byte-level IKEv1/IKEv2 message builders used by the synthetic testbed (RFC 2408/2409/7296 wire formats)."""
from __future__ import annotations

import os
import struct

# ---------------------------------------------------------------------------- generic

def hdr(spi_i: bytes, spi_r: bytes, first: int, version: int, exch: int, flags: int, msg_id: int, body: bytes) -> bytes:
    ver = 0x20 if version == 2 else 0x10
    return struct.pack("!8s8sBBBBII", spi_i, spi_r, first, ver, exch, flags, msg_id, 28 + len(body)) + body


def chain(payloads: list[tuple[int, bytes]]) -> tuple[int, bytes]:
    """payloads: [(type, body)] -> (first_type, bytes) with correct next-payload links."""
    if not payloads:
        return 0, b""
    out = b""
    for i, (t, body) in enumerate(payloads):
        nxt = payloads[i + 1][0] if i + 1 < len(payloads) else 0
        out += struct.pack("!BBH", nxt, 0, 4 + len(body)) + body
    return payloads[0][0], out


def message(spi_i, spi_r, version, exch, flags, msg_id, payloads) -> bytes:
    first, body = chain(payloads)
    return hdr(spi_i, spi_r, first, version, exch, flags, msg_id, body)


# ---------------------------------------------------------------------------- IKEv2 payloads

def attr_keylen(bits: int) -> bytes:
    return struct.pack("!HH", 0x8000 | 14, bits)


def v2_transform(ttype: int, tid: int, keylen: int | None = None) -> bytes:
    attrs = attr_keylen(keylen) if keylen else b""
    return struct.pack("!BBHBBH", 0, 0, 8 + len(attrs), ttype, 0, tid) + attrs


def v2_proposal(num: int, proto: int, spi: bytes, transforms: list[tuple]) -> bytes:
    tb = b""
    for i, t in enumerate(transforms):
        raw = v2_transform(*t)
        more = 3 if i + 1 < len(transforms) else 0
        tb += bytes([more]) + raw[1:]
    return struct.pack("!BBHBBBB", 0, 0, 8 + len(spi) + len(tb), num, proto, len(spi), len(transforms)) + spi + tb


def v2_sa(proposals: list[tuple]) -> bytes:
    """proposals: [(proto, spi, [(ttype, tid, keylen?), ...])]"""
    out = b""
    for i, (proto, spi, trans) in enumerate(proposals):
        raw = v2_proposal(i + 1, proto, spi, trans)
        more = 2 if i + 1 < len(proposals) else 0
        out += bytes([more]) + raw[1:]
    return out


def v2_ke(group: int, pub_len: int) -> bytes:
    return struct.pack("!HH", group, 0) + os.urandom(pub_len)


def v2_nonce(n: int = 32) -> bytes:
    return os.urandom(n)


def v2_notify(ntype: int, data: bytes = b"", proto: int = 0, spi: bytes = b"") -> bytes:
    return struct.pack("!BBH", proto, len(spi), ntype) + spi + data


def v2_vid(v: bytes) -> bytes:
    return v


def v2_certreq(n_hashes: int = 1) -> bytes:
    return b"\x04" + os.urandom(20 * n_hashes)


def sk_len_for(plain_len: int, iv: int, icv: int, block: int) -> int:
    """Length of an SK payload body for `plain_len` bytes of inner payloads."""
    c = plain_len + 1                   # pad length byte
    pad = (-c) % block
    return iv + c + pad + icv


def v2_sk(plain_len: int, iv: int = 8, icv: int = 16, block: int = 4) -> bytes:
    return os.urandom(sk_len_for(plain_len, iv, icv, block))


# ---------------------------------------------------------------------------- IKEv1 payloads

def v1_attr_tv(t: int, v: int) -> bytes:
    return struct.pack("!HH", 0x8000 | t, v)


def v1_attr_tlv(t: int, v: bytes) -> bytes:
    return struct.pack("!HH", t, len(v)) + v


def v1_transform(num: int, attrs: dict) -> bytes:
    a = b""
    for k in (1, 14, 2, 3, 4, 11, 12):
        if k in attrs:
            if k == 12:
                a += v1_attr_tlv(12, struct.pack("!I", attrs[12]))
            else:
                a += v1_attr_tv(k, attrs[k])
    return struct.pack("!BBHBBH", 0, 0, 8 + len(a), num, 1, 0) + a


def v1_sa(transforms: list[dict], doi: int = 1, situation: int = 1) -> bytes:
    """Phase-1 SA with a single proposal and N transforms (each a dict of ISAKMP attributes)."""
    tb = b""
    for i, t in enumerate(transforms):
        raw = v1_transform(i + 1, t)
        more = 3 if i + 1 < len(transforms) else 0
        tb += bytes([more]) + raw[1:]
    prop = struct.pack("!BBHBBBB", 0, 0, 8 + len(tb), 1, 1, 0, len(transforms)) + tb
    return struct.pack("!II", doi, situation) + prop


def v1_ke(pub_len: int) -> bytes:
    return os.urandom(pub_len)


def v1_nonce(n: int = 32) -> bytes:
    return os.urandom(n)


def v1_id(id_type: int, value: bytes, proto: int = 17, port: int = 500) -> bytes:
    return struct.pack("!BBH", id_type, proto, port) + value


def v1_hash(n: int = 20) -> bytes:
    return os.urandom(n)


def v1_natd() -> bytes:
    return os.urandom(20)


def v1_encrypted(spi_i, spi_r, exch: int, msg_id: int, plain_len: int, block: int = 8, next_payload: int = 8) -> bytes:
    c = plain_len
    pad = (-c) % block
    body = os.urandom(c + pad)
    return hdr(spi_i, spi_r, next_payload, 1, exch, 0x01, msg_id, body)


# vendor ids (hex)
VID_NATT_RFC3947 = bytes.fromhex("4a131c81070358455c5728f20e95452f")
VID_DPD = bytes.fromhex("afcad71368a1f1c96b8696fc77570100")
VID_XAUTH = bytes.fromhex("09002689dfd6b712")
VID_STRONGSWAN = bytes.fromhex("882fe56d6fd20dbc2251613b2ebe5beb")
VID_CISCO_UNITY = bytes.fromhex("12f5f28c457168a9702d9fe274cc0100")
VID_FRAG = bytes.fromhex("4048b7d56ebce88525e7de7f00d6c2d3")
