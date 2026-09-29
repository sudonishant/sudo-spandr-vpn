"""Synthetic-but-physically-correct IPsec scenario generator.

    python -m ipsec_xray.testbed.generate [--out samples] [--seed 1]

Every scenario writes  <name>.pcap  plus ground truth in  manifest.json  (used by the tests and shown in the dashboard as
"expected vs inferred").  IKE messages are real RFC-conformant byte structures (parseable by Wireshark); ESP payloads are
random bytes whose *lengths* follow the exact RFC 4303 framing of the chosen cipher suite, so every length-based inference
in the analyzer is exercised against known truth.  Real captures from the strongSwan testbed (testbed/strongswan) drop in
unchanged.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import struct
import time

from scapy.all import Ether, IP, IPv6, UDP, Raw, PcapWriter  # noqa

from ..analysis.physics import CAND_BY_KEY, esp_length_for
from ..ml.simulate import frame_esp, simulate
from . import ikebuild as B

T0 = 1_790_000_000.0   # capture epoch (2026)


class Writer:
    def __init__(self, path: str, snaplen: int | None = None):
        self.w = PcapWriter(path, linktype=1, sync=False)
        self.snaplen = snaplen
        self.count = 0

    def add(self, pkt, ts: float, truncatable: bool = False):
        pkt.time = ts
        raw = bytes(pkt)
        if truncatable and self.snaplen and len(raw) > self.snaplen:
            p = Ether(raw[:self.snaplen])
            p.wirelen = len(raw)
            p.time = ts
            self.w.write(p)
        else:
            self.w.write(pkt)
        self.count += 1

    def close(self):
        self.w.close()


def _mac(ip: str) -> str:
    h = sum(ord(c) * (i + 1) for i, c in enumerate(ip)) % 0xFFFFFF
    return "02:00:%02x:%02x:%02x:%02x" % (0, (h >> 16) & 0xFF, (h >> 8) & 0xFF, h & 0xFF)


def _l3(src: str, dst: str, ipver: int, proto: int | None = None):
    e = Ether(src=_mac(src), dst=_mac(dst))
    if ipver == 6:
        ip = IPv6(src=src, dst=dst, hlim=64)
        if proto is not None:
            ip.nh = proto
    else:
        ip = IP(src=src, dst=dst, ttl=64, id=random.randint(1, 65000))
        if proto is not None:
            ip.proto = proto
    return e / ip


def udp(src, dst, sport, dport, payload: bytes, ipver=4):
    return _l3(src, dst, ipver) / UDP(sport=sport, dport=dport) / Raw(payload)


APP_INNER = {   # application class -> (proto, server port) used inside NULL-ESP / AH cleartext packets
    "icmp": (1, None), "voip": (17, 5060), "video": (17, 443), "web": (6, 443), "email": (6, 993),
    "chat": (6, 5222), "file": (6, 445), "ssh": (6, 22),
}


def _inner_packet(length: int, app: str | None, ipver_inner: int, with_ip_header: bool) -> bytes:
    """Cleartext inner packet of exactly `length` bytes: IP header (tunnel mode) + transport header + low-entropy body."""
    proto, port = APP_INNER.get(app or "web", (6, 443))
    body = b""
    if with_ip_header:
        if ipver_inner == 4 and length >= 20:
            body = bytes([0x45, 0x00]) + struct.pack("!H", length) + os.urandom(2) + b"\x40\x00\x40" + bytes([proto]) + b"\x00\x00" + os.urandom(8)
        elif ipver_inner == 6 and length >= 40:
            proto6 = 58 if proto == 1 else proto
            body = bytes([0x60, 0x00, 0x00, 0x00]) + struct.pack("!H", max(0, length - 40)) + bytes([proto6, 64]) + os.urandom(32)
    if len(body) + 8 <= length:
        if proto in (6, 17):
            cport = random.randint(32768, 60999)
            body += struct.pack("!HH", cport, port) if random.random() < 0.5 else struct.pack("!HH", port, cport)
            body += (struct.pack("!IIBBHHH", random.randint(1, 2**32 - 1), random.randint(1, 2**32 - 1), 0x50, 0x18, 65535, 0, 0)
                     if proto == 6 else struct.pack("!HH", max(8, length - len(body) - 4), 0))
        else:
            body += bytes([8 if random.random() < 0.5 else 0, 0]) + os.urandom(2) + struct.pack("!HH", random.randint(1, 65535), random.randint(1, 65535))
    filler = bytes(random.choice(b"abcdefghijklmnopqrstuvwxyz ETAOIN\x00\x00\x00") for _ in range(max(0, length - len(body))))
    return (body + filler)[:length]


def esp_pkt(src, dst, spi: int, seq: int, total_len: int, ipver=4, natt=False, plaintext=False, inner_hdr=True, ipver_inner=4,
            icv_len: int = 12, app: str | None = None):
    n = max(0, total_len - 8)
    if plaintext:
        # NULL encryption (RFC 4303 with ENCR_NULL): no IV; [inner packet | pad 1,2,3.. | pad-length | next-header | ICV]
        m = n - icv_len                       # = P + 2 + pad  (multiple of 4 by construction of the forward model)
        pad = m % 4                           # keep the trailer 4-byte aligned whatever the caller passed
        p_len = max(0, m - 2 - pad)
        proto, _ = APP_INNER.get(app or "web", (6, 443))
        next_header = (4 if ipver_inner == 4 else 41) if inner_hdr else (58 if (ipver_inner == 6 and proto == 1) else proto)
        inner = _inner_packet(p_len, app, ipver_inner, inner_hdr)
        payload = inner + bytes(range(1, pad + 1)) + bytes([pad, next_header]) + os.urandom(icv_len)
        payload = payload[:n].ljust(n, b"\x00")
        body = struct.pack("!II", spi, seq) + payload
    else:
        body = struct.pack("!II", spi, seq) + os.urandom(n)
    if natt:
        return udp(src, dst, 4500, 4500, body, ipver)
    return _l3(src, dst, ipver, proto=50) / Raw(body)


def ah_pkt(src, dst, spi: int, seq: int, inner_len: int, icv_len: int, next_header: int, ipver=4):
    plen = (12 + icv_len) // 4 - 2
    body = struct.pack("!BBHII", next_header, plen, 0, spi, seq) + os.urandom(icv_len) + os.urandom(inner_len)
    return _l3(src, dst, ipver, proto=51) / Raw(body)


# ---------------------------------------------------------------------------- IKEv2 conversation

class IKEv2Peer:
    def __init__(self, wr: Writer, init: str, resp: str, ipver=4, natt=False, ike_encr=("aead", 8, 16, 4)):
        self.wr, self.init, self.resp, self.ipver, self.natt = wr, init, resp, ipver, natt
        self.spi_i, self.spi_r = os.urandom(8), os.urandom(8)
        self.msg_id = 0
        self.port = 4500 if natt else 500
        _, self.iv, self.icv, self.block = ike_encr

    def _send(self, direction: str, data: bytes, ts: float):
        src, dst = (self.init, self.resp) if direction == "i" else (self.resp, self.init)
        if self.natt:
            data = b"\x00\x00\x00\x00" + data
        self.wr.add(udp(src, dst, self.port, self.port, data, self.ipver), ts)

    def sa_init(self, ts: float, offered: list, chosen: list, ke: tuple, notifies_i=(), notifies_r=(), certreq=False, vids=(),
                add_ke: list | None = None, resp_spi_r=None):
        """offered/chosen: list of proposals [(proto, spi, [(ttype,tid,keylen)])]; ke=(group,len)."""
        spi0 = b"\x00" * 8
        pl = [(33, B.v2_sa(offered)), (34, B.v2_ke(*ke)), (40, B.v2_nonce(32)),
              (41, B.v2_notify(16388, os.urandom(20))), (41, B.v2_notify(16389, os.urandom(20)))]
        for n in notifies_i:
            pl.append((41, B.v2_notify(*n) if isinstance(n, tuple) else B.v2_notify(n)))
        for v in vids:
            pl.append((43, v))
        self._send("i", B.message(self.spi_i, spi0, 2, 34, 0x08, 0, pl), ts)
        pl = [(33, B.v2_sa(chosen)), (34, B.v2_ke(*ke)), (40, B.v2_nonce(32)),
              (41, B.v2_notify(16388, os.urandom(20))), (41, B.v2_notify(16389, os.urandom(20)))]
        for n in notifies_r:
            pl.append((41, B.v2_notify(*n) if isinstance(n, tuple) else B.v2_notify(n)))
        if certreq:
            pl.append((38, B.v2_certreq(2)))
        self._send("r", B.message(self.spi_i, self.spi_r, 2, 34, 0x20, 0, pl), ts + random.uniform(0.01, 0.04))
        self.msg_id = 1
        return ts + 0.05

    def intermediate(self, ts: float, plain_len_i: int, plain_len_r: int):
        self._send("i", B.message(self.spi_i, self.spi_r, 2, 43, 0x08, self.msg_id, [(46, B.v2_sk(plain_len_i, self.iv, self.icv, self.block))]), ts)
        self._send("r", B.message(self.spi_i, self.spi_r, 2, 43, 0x20, self.msg_id, [(46, B.v2_sk(plain_len_r, self.iv, self.icv, self.block))]), ts + 0.03)
        self.msg_id += 1
        return ts + 0.05

    def ike_auth(self, ts: float, plain_len_i: int, plain_len_r: int, rounds: int = 1):
        for r in range(rounds):
            li = plain_len_i if r == 0 else random.randint(60, 120)
            lr = plain_len_r if r == rounds - 1 else random.randint(60, 140)
            self._send("i", B.message(self.spi_i, self.spi_r, 2, 35, 0x08, self.msg_id, [(46, B.v2_sk(li, self.iv, self.icv, self.block))]), ts)
            self._send("r", B.message(self.spi_i, self.spi_r, 2, 35, 0x20, self.msg_id, [(46, B.v2_sk(lr, self.iv, self.icv, self.block))]), ts + 0.04)
            self.msg_id += 1
            ts += 0.08
        return ts

    def child_rekey(self, ts: float, pfs_pub_len: int | None, n_proposals: int = 1, ts_count: int = 1):
        # plaintext: N(REKEY_SA) 12 + SA + Ni 36 + TSi/TSr (+KE)
        sa_len = 4 + n_proposals * (8 + 4 + 12 + 8)
        tsl = 2 * (8 + ts_count * 16)
        plain = 12 + sa_len + 36 + tsl + ((8 + pfs_pub_len) if pfs_pub_len else 0)
        self._send("i", B.message(self.spi_i, self.spi_r, 2, 36, 0x08, self.msg_id, [(46, B.v2_sk(plain, self.iv, self.icv, self.block))]), ts)
        self._send("r", B.message(self.spi_i, self.spi_r, 2, 36, 0x20, self.msg_id, [(46, B.v2_sk(plain - 12, self.iv, self.icv, self.block))]), ts + 0.03)
        self.msg_id += 1
        return ts + 0.05

    def informational(self, ts: float, plain_len: int = 0):
        self._send("i", B.message(self.spi_i, self.spi_r, 2, 37, 0x08, self.msg_id, [(46, B.v2_sk(plain_len, self.iv, self.icv, self.block))]), ts)
        self._send("r", B.message(self.spi_i, self.spi_r, 2, 37, 0x20, self.msg_id, [(46, B.v2_sk(plain_len, self.iv, self.icv, self.block))]), ts + 0.02)
        self.msg_id += 1


# ---------------------------------------------------------------------------- IKEv1 conversation

class IKEv1Peer:
    def __init__(self, wr: Writer, init: str, resp: str, block: int = 8):
        self.wr, self.init, self.resp = wr, init, resp
        self.spi_i, self.spi_r = os.urandom(8), os.urandom(8)
        self.block = block

    def _send(self, direction, data, ts):
        src, dst = (self.init, self.resp) if direction == "i" else (self.resp, self.init)
        self.wr.add(udp(src, dst, 500, 500, data), ts)

    def main_mode(self, ts, offered: list[dict], chosen: dict, pub_len: int, vids=()):
        spi0 = b"\x00" * 8
        pl = [(1, B.v1_sa(offered))] + [(13, v) for v in vids]
        self._send("i", B.message(self.spi_i, spi0, 1, 2, 0, 0, pl), ts)
        pl = [(1, B.v1_sa([chosen]))] + [(13, v) for v in vids]
        self._send("r", B.message(self.spi_i, self.spi_r, 1, 2, 0, 0, pl), ts + 0.02)
        self._send("i", B.message(self.spi_i, self.spi_r, 1, 2, 0, 0, [(4, B.v1_ke(pub_len)), (10, B.v1_nonce(20)), (20, B.v1_natd()), (20, B.v1_natd())]), ts + 0.05)
        self._send("r", B.message(self.spi_i, self.spi_r, 1, 2, 0, 0, [(4, B.v1_ke(pub_len)), (10, B.v1_nonce(20)), (20, B.v1_natd()), (20, B.v1_natd())]), ts + 0.09)
        self._send("i", B.v1_encrypted(self.spi_i, self.spi_r, 2, 0, 12 + 8 + 24, self.block, 5), ts + 0.12)
        self._send("r", B.v1_encrypted(self.spi_i, self.spi_r, 2, 0, 12 + 8 + 24, self.block, 5), ts + 0.15)
        return ts + 0.2

    def aggressive_mode(self, ts, offered: list[dict], chosen: dict, pub_len: int, id_i: bytes, id_r: bytes, vids=()):
        spi0 = b"\x00" * 8
        pl = [(1, B.v1_sa(offered)), (4, B.v1_ke(pub_len)), (10, B.v1_nonce(20)), (5, B.v1_id(2, id_i))] + [(13, v) for v in vids]
        self._send("i", B.message(self.spi_i, spi0, 1, 4, 0, 0, pl), ts)
        pl = [(1, B.v1_sa([chosen])), (4, B.v1_ke(pub_len)), (10, B.v1_nonce(20)), (5, B.v1_id(2, id_r)), (8, B.v1_hash(20))] + \
             [(13, v) for v in vids] + [(20, B.v1_natd()), (20, B.v1_natd())]
        self._send("r", B.message(self.spi_i, self.spi_r, 1, 4, 0, 0, pl), ts + 0.03)
        self._send("i", B.v1_encrypted(self.spi_i, self.spi_r, 4, 0, 24 + 40, self.block, 8), ts + 0.06)
        return ts + 0.1

    def quick_mode(self, ts, pfs_pub_len: int | None):
        mid = random.randint(1, 2 ** 31)
        plain = 24 + 64 + 24 + 12 + 12 + ((4 + pfs_pub_len) if pfs_pub_len else 0)
        self._send("i", B.v1_encrypted(self.spi_i, self.spi_r, 32, mid, plain, self.block), ts)
        self._send("r", B.v1_encrypted(self.spi_i, self.spi_r, 32, mid, plain, self.block), ts + 0.03)
        self._send("i", B.v1_encrypted(self.spi_i, self.spi_r, 32, mid, 24, self.block), ts + 0.05)
        return ts + 0.08

    def dpd(self, ts):
        self._send("i", B.v1_encrypted(self.spi_i, self.spi_r, 5, random.randint(1, 2 ** 31), 24 + 16, self.block, 11), ts)
        self._send("r", B.v1_encrypted(self.spi_i, self.spi_r, 5, random.randint(1, 2 ** 31), 24 + 16, self.block, 11), ts + 0.02)


# ---------------------------------------------------------------------------- ESP traffic helper

def write_esp_traffic(wr: Writer, init: str, resp: str, events: list, cand_key: str, mode: str, ipver: int, t_start: float,
                      natt=False, spi_up=None, spi_down=None, seq_start=(1, 1), rekey_every: float | None = None,
                      rekey_cb=None, anomaly=None, default_app=None):
    """events: (t, dir, inner_len[, app]) relative; returns list of SPI epochs [(t0, spi_up, spi_down)]."""
    cand = CAND_BY_KEY[cand_key]
    framed = frame_esp(events, cand, mode, ipver)
    spi_up = spi_up or random.randint(0x10000000, 0xFFFFFFFF)
    spi_down = spi_down or random.randint(0x10000000, 0xFFFFFFFF)
    seq = {"up": seq_start[0], "down": seq_start[1]}
    epochs = [(t_start, spi_up, spi_down)]
    next_rekey = rekey_every
    pkts_out = []
    for fr in framed:
        t, d, total = fr[0], fr[1], fr[2]
        app = fr[3] if len(fr) > 3 else default_app
        if rekey_every and t >= next_rekey:
            if rekey_cb:
                rekey_cb(t_start + next_rekey)
            spi_up, spi_down = random.randint(0x10000000, 0xFFFFFFFF), random.randint(0x10000000, 0xFFFFFFFF)
            seq = {"up": 1, "down": 1}
            epochs.append((t_start + next_rekey, spi_up, spi_down))
            next_rekey += rekey_every
        src, dst, spi = (init, resp, spi_up) if d == "up" else (resp, init, spi_down)
        pkts_out.append((t_start + t, src, dst, spi, seq[d], total, app))
        seq[d] += 1
    if anomaly == "replay":
        # duplicate a slice of packets (replayed later) and a decreasing burst
        dup = [p for p in pkts_out[200:230]]
        pkts_out += [(p[0] + 2.0, p[1], p[2], p[3], p[4], p[5], p[6]) for p in dup]
        base = pkts_out[600]
        for k in range(10):
            pkts_out.append((base[0] + 0.001 * k, base[1], base[2], base[3], max(1, base[4] - 50 - k), base[5], base[6]))
        pkts_out.sort(key=lambda p: p[0])
    for ts, src, dst, spi, sq, total, app in pkts_out:
        wr.add(esp_pkt(src, dst, spi, sq, total, ipver, natt, plaintext=(cand.family == "null"), inner_hdr=(mode == "tunnel"), ipver_inner=ipver,
                       icv_len=cand.icv or 12, app=app), ts, truncatable=True)
    return epochs


# ---------------------------------------------------------------------------- proposals

def P(proto, spi, *trans):
    return (proto, spi, list(trans))


IKE_GCM256_ECP384 = P(1, b"", (1, 20, 256), (2, 6), (4, 20), (6, 37))
IKE_GCM256_ECP384_offer2 = P(1, b"", (1, 20, 256), (2, 6), (4, 20))
IKE_GCM128_MODP2048 = P(1, b"", (1, 20, 128), (2, 5), (4, 14))
IKE_CBC256_SHA256_MODP2048 = P(1, b"", (1, 12, 256), (2, 5), (3, 12), (4, 14))
IKE_CBC128_SHA1_MODP2048 = P(1, b"", (1, 12, 128), (2, 2), (3, 2), (4, 14))
IKE_CBC128_SHA1_MODP1024 = P(1, b"", (1, 12, 128), (2, 2), (3, 2), (4, 2))
IKE_3DES_SHA1_MODP1024 = P(1, b"", (1, 3), (2, 2), (3, 2), (4, 2))
IKE_CHACHA_SHA512_X25519 = P(1, b"", (1, 28), (2, 7), (4, 31))
IKE_CBC256_SHA384_ECP384 = P(1, b"", (1, 12, 256), (2, 6), (3, 13), (4, 20))

N_FRAG = 16430
N_SIGHASH = (16431, struct.pack("!HHH", 2, 3, 4))
N_SIGHASH_SHA1 = (16431, struct.pack("!HHHH", 1, 2, 3, 4))
N_INTERMEDIATE = 16438
N_MOBIKE = 16396
N_REDIRECT = 16406
N_COOKIE = (16390, os.urandom(32))


# ---------------------------------------------------------------------------- scenarios

def scen_good(out, seed):
    """A+ : IKEv2, AES-GCM-256, ECP-384 + ML-KEM-1024 hybrid, PFS rekeys, certificates, VoIP."""
    wr = Writer(out)
    init, resp = "10.10.1.20", "198.51.100.5"
    p = IKEv2Peer(wr, init, resp)
    ts = T0
    ts = p.sa_init(ts, [IKE_GCM256_ECP384, IKE_GCM256_ECP384_offer2], [IKE_GCM256_ECP384], (20, 96),
                   notifies_i=[N_FRAG, N_SIGHASH, N_INTERMEDIATE], notifies_r=[N_FRAG, N_SIGHASH, N_INTERMEDIATE], certreq=True)
    ts = p.intermediate(ts, 8 + 1568, 8 + 1568)            # ML-KEM-1024 encapsulation keys / ciphertext
    ts = p.ike_auth(ts, 12 + 8 + 384 + 1100 + 40 + 48 + 48, 12 + 8 + 384 + 1100 + 40 + 48 + 48)
    events = simulate("voip", 60, seed)
    write_esp_traffic(wr, init, resp, events, "aead_16", "tunnel", 4, ts + 0.5, rekey_every=20.0,
                      rekey_cb=lambda t: p.child_rekey(t - 0.2, 96, n_proposals=2, ts_count=2))
    for k in range(1, 3):
        p.informational(ts + 25 * k)
    wr.close()
    return {"ike_version": 2, "ike": "AES_GCM_16-256 / PRF_HMAC_SHA2_384 / ECP-384 + ML-KEM-1024", "esp_framing": "o24_b4",
            "esp": "AES-GCM-16 (AEAD)", "mode": "tunnel", "traffic": "voip", "pfs": "on", "pfs_group": "ECP-384", "ipver": 4,
            "expected_grade": ["A+", "A"], "description": "Best-practice IKEv2 site-to-site tunnel: AES-256-GCM, ECP-384 with ML-KEM-1024 hybrid key exchange, certificate auth, PFS on every rekey, VoIP call inside."}


def scen_enterprise(out, seed):
    """B : IKEv2 AES-CBC-256/SHA-256/MODP-2048 with weaker fallbacks offered, NAT-T, no PFS, web browsing."""
    wr = Writer(out)
    init, resp = "192.168.7.44", "203.0.113.10"
    p = IKEv2Peer(wr, init, resp, natt=True, ike_encr=("cbc", 16, 16, 16))
    ts = T0
    ts = p.sa_init(ts, [IKE_CBC256_SHA256_MODP2048, IKE_CBC128_SHA1_MODP2048, IKE_CBC128_SHA1_MODP1024], [IKE_CBC256_SHA256_MODP2048], (14, 256),
                   notifies_i=[N_FRAG, N_SIGHASH_SHA1], notifies_r=[N_FRAG, N_SIGHASH_SHA1], vids=[B.VID_STRONGSWAN])
    ts = p.ike_auth(ts, 12 + 8 + 32 + 40 + 24 + 24 + 8, 12 + 8 + 32 + 40 + 24 + 24)   # PSK-sized AUTH
    events = simulate("web", 70, seed)
    write_esp_traffic(wr, init, resp, events, "aes_cbc_sha256", "tunnel", 4, ts + 0.5, natt=True, rekey_every=30.0,
                      rekey_cb=lambda t: p.child_rekey(t - 0.2, None))
    # NAT keepalives
    for k in range(1, 4):
        wr.add(udp(init, resp, 4500, 4500, b"\xff"), ts + 20 * k)
    wr.close()
    return {"ike_version": 2, "ike": "AES_CBC-256 / HMAC_SHA2_256_128 / MODP-2048", "esp_framing": "o32_b16", "esp": "AES-CBC + HMAC-SHA2-256-128",
            "mode": "tunnel", "traffic": "web", "pfs": "off", "ipver": 4, "expected_grade": ["B", "C"],
            "description": "Typical enterprise remote-access profile: AES-CBC-256 + SHA-256 + MODP-2048, but weak fallbacks (SHA-1, MODP-1024) still offered, PSK-sized auth, Child SA rekey without PFS, NAT-T."}


def scen_legacy_v1(out, seed):
    """D/F : IKEv1 aggressive mode, PSK+XAUTH, 3DES/SHA1/MODP-1024, identity leak, e-mail traffic."""
    wr = Writer(out)
    init, resp = "172.16.5.9", "203.0.113.77"
    p = IKEv1Peer(wr, init, resp, block=8)
    ts = T0
    t_3des = {1: 5, 2: 2, 3: 65001, 4: 2, 11: 1, 12: 86400}
    t_aes = {1: 7, 14: 128, 2: 2, 3: 65001, 4: 2, 11: 1, 12: 86400}
    ts = p.aggressive_mode(ts, [t_3des, t_aes], t_3des, 128, b"branch-office-12@corp.example.in", b"vpn-gw.corp.example.in",
                           vids=[B.VID_XAUTH, B.VID_DPD, B.VID_NATT_RFC3947, B.VID_CISCO_UNITY])
    ts = p.quick_mode(ts, None)
    events = simulate("email", 90, seed)
    write_esp_traffic(wr, init, resp, events, "des3_sha1", "tunnel", 4, ts + 0.3, rekey_every=45.0, rekey_cb=lambda t: p.quick_mode(t - 0.2, None))
    for k in range(1, 4):
        p.dpd(ts + 30 * k)
    wr.close()
    return {"ike_version": 1, "ike": "3DES_CBC / SHA1 / MODP-1024, aggressive mode, XAUTH-PSK", "esp_framing": "o20_b8", "esp": "3DES-CBC + HMAC-SHA1-96",
            "mode": "tunnel", "traffic": "email", "pfs": "off", "ipver": 4, "expected_grade": ["F", "D"],
            "description": "Legacy Cisco-style remote access: IKEv1 aggressive mode with XAUTH/PSK (offline PSK cracking), 3DES/SHA-1/MODP-1024 (Sweet32 + Logjam class), identities leaked in cleartext, no PFS."}


def scen_terrible_v1(out, seed):
    """F : IKEv1 main mode DES/MD5/MODP-768, ESP NULL encryption + MD5, ICMP + file transfer."""
    wr = Writer(out)
    init, resp = "10.0.0.2", "10.0.0.1"
    p = IKEv1Peer(wr, init, resp, block=8)
    ts = T0
    t_des = {1: 1, 2: 1, 3: 1, 4: 1, 11: 1, 12: 28800}
    ts = p.main_mode(ts, [t_des], t_des, 96, vids=[B.VID_DPD])
    ts = p.quick_mode(ts, None)
    ev = [(t, d, n, "icmp") for t, d, n in simulate("icmp", 40, seed)] + [(t + 12, d, n, "file") for t, d, n in simulate("file", 5, seed + 1)]
    ev.sort(key=lambda e: e[0])
    write_esp_traffic(wr, init, resp, ev, "null_sha1", "tunnel", 4, ts + 0.3)
    wr.close()
    return {"ike_version": 1, "ike": "DES_CBC / MD5 / MODP-768, main mode, PSK", "esp_framing": "o12_b4", "esp": "NULL encryption + HMAC-MD5-96",
            "mode": "tunnel", "traffic": "icmp+file", "pfs": "off", "ipver": 4, "expected_grade": ["F"],
            "description": "Worst case: DES/MD5/MODP-768 IKEv1 and ESP with NULL encryption - traffic is authenticated but readable by anyone on the path."}


def scen_ipv6_natt_chacha(out, seed):
    """A/B : IPv6, IKEv2 ChaCha20-Poly1305/X25519, MOBIKE, transport mode, SSH + chat, PFS with ECP-256."""
    wr = Writer(out)
    init, resp = "2001:db8:1::20", "2001:db8:2::10"
    p = IKEv2Peer(wr, init, resp, ipver=6, natt=True)
    ts = T0
    ts = p.sa_init(ts, [IKE_CHACHA_SHA512_X25519, IKE_GCM128_MODP2048], [IKE_CHACHA_SHA512_X25519], (31, 32),
                   notifies_i=[N_FRAG, N_SIGHASH, N_MOBIKE], notifies_r=[N_FRAG, N_SIGHASH, N_MOBIKE, N_REDIRECT])
    ts = p.ike_auth(ts, 12 + 8 + 256 + 900 + 40 + 24 + 24 + 8, 12 + 8 + 256 + 900 + 40 + 24 + 24)
    ev = simulate("ssh", 60, seed, ipver=6) + [(t, d, n) for t, d, n in simulate("chat", 60, seed + 3, ipver=6)]
    ev.sort(key=lambda e: e[0])
    write_esp_traffic(wr, init, resp, ev, "aead_16", "transport", 6, ts + 0.5, natt=True, rekey_every=25.0,
                      rekey_cb=lambda t: p.child_rekey(t - 0.2, 64, n_proposals=2, ts_count=2))
    wr.close()
    return {"ike_version": 2, "ike": "CHACHA20_POLY1305 / PRF_HMAC_SHA2_512 / X25519", "esp_framing": "o24_b4", "esp": "ChaCha20-Poly1305 (AEAD)",
            "mode": "transport", "traffic": "ssh+chat", "pfs": "on", "pfs_group": "ECP-256", "ipver": 6, "expected_grade": ["A+", "A"],
            "description": "Modern host-to-host IPsec over IPv6 with UDP encapsulation: ChaCha20-Poly1305, X25519, MOBIKE, transport mode, PFS via ECP-256; carries an SSH session and chat traffic."}


def scen_ah_only(out, seed):
    """D/F : IKEv2 fine, but the Child SA is AH-only (integrity, no confidentiality)."""
    wr = Writer(out)
    init, resp = "10.20.0.5", "10.20.0.1"
    p = IKEv2Peer(wr, init, resp, ike_encr=("cbc", 16, 16, 16))
    ts = T0
    ts = p.sa_init(ts, [IKE_CBC256_SHA256_MODP2048], [IKE_CBC256_SHA256_MODP2048], (14, 256), notifies_i=[N_FRAG], notifies_r=[N_FRAG])
    ts = p.ike_auth(ts, 12 + 8 + 32 + 40 + 24 + 24, 12 + 8 + 32 + 40 + 24 + 24)
    ev = simulate("icmp", 45, seed)
    spi_up, spi_down = random.randint(1 << 28, (1 << 32) - 1), random.randint(1 << 28, (1 << 32) - 1)
    seq = {"up": 1, "down": 1}
    for t, d, inner in ev:
        src, dst, spi = (init, resp, spi_up) if d == "up" else (resp, init, spi_down)
        wr.add(ah_pkt(src, dst, spi, seq[d], inner - 20, 12, 1), ts + 0.4 + t, truncatable=True)   # transport mode: inner = ICMP only
        seq[d] += 1
    wr.close()
    return {"ike_version": 2, "ike": "AES_CBC-256 / HMAC_SHA2_256_128 / MODP-2048", "esp_framing": None, "esp": "AH only, HMAC-SHA1-96",
            "mode": "transport", "traffic": "icmp", "pfs": "unknown", "ipver": 4, "expected_grade": ["F", "D"],
            "description": "Authentication Header only: packets are integrity-protected but every byte of the payload travels in cleartext."}


def scen_replay_anomaly(out, seed):
    """C : enterprise-like tunnel with replayed / out-of-order ESP, an IKE_SA_INIT flood and a malformed IKE message; snaplen-truncated capture."""
    wr = Writer(out, snaplen=128)
    init, resp = "192.168.44.12", "203.0.113.200"
    p = IKEv2Peer(wr, init, resp)
    ts = T0
    ts = p.sa_init(ts, [IKE_GCM128_MODP2048, IKE_CBC128_SHA1_MODP2048], [IKE_GCM128_MODP2048], (14, 256), notifies_i=[N_FRAG, N_SIGHASH],
                   notifies_r=[N_FRAG, N_SIGHASH])
    ts = p.ike_auth(ts, 12 + 8 + 256 + 40 + 24 + 24, 12 + 8 + 256 + 40 + 24 + 24)
    ev = simulate("video", 30, seed)
    write_esp_traffic(wr, init, resp, ev, "aead_16", "tunnel", 4, ts + 0.5, anomaly="replay")
    # IKE_SA_INIT flood from spoofed sources, responder answers with COOKIE
    for k in range(60):
        src = f"45.{random.randint(1, 250)}.{random.randint(1, 250)}.{random.randint(1, 250)}"
        spi = os.urandom(8)
        m = B.message(spi, b"\x00" * 8, 2, 34, 0x08, 0, [(33, B.v2_sa([IKE_GCM128_MODP2048])), (34, B.v2_ke(14, 256)), (40, B.v2_nonce(32))])
        wr.add(udp(src, resp, random.randint(1024, 65000), 500, m), ts + 5 + k * 0.05)
        if k % 3 == 0:
            r = B.message(spi, b"\x00" * 8, 2, 34, 0x20, 0, [(41, B.v2_notify(*N_COOKIE))])
            wr.add(udp(resp, src, 500, 1024 + k, r), ts + 5 + k * 0.05 + 0.002)
    # malformed IKE message: payload length larger than the message
    bad = B.message(p.spi_i, p.spi_r, 2, 37, 0x08, 99, [(46, os.urandom(40))])
    bad = bad[:28] + struct.pack("!BBH", 0, 0, 900) + bad[32:]
    wr.add(udp(init, resp, 500, 500, bad), ts + 12)
    # cleartext DNS + HTTP between the same peers (policy leak)
    for k in range(5):
        wr.add(udp(init, resp, 40000 + k, 53, os.urandom(40)), ts + 14 + k)
    wr.close()
    return {"ike_version": 2, "ike": "AES_GCM_16-128 / PRF_HMAC_SHA2_256 / MODP-2048", "esp_framing": "o24_b4", "esp": "AES-GCM-16 (AEAD)",
            "mode": "tunnel", "traffic": "video", "pfs": "unknown", "ipver": 4, "expected_grade": ["C", "B", "D"],
            "description": "Operational anomalies: replayed and decreasing ESP sequence numbers, an IKE_SA_INIT flood answered with cookies, a malformed IKE packet and cleartext traffic beside the tunnel. ESP packets are snaplen-truncated to 128 B to show that the length physics survives truncated captures."}


def scen_hub(out, seed):
    """Mixed: one hub, three spokes, three traffic types (video / chat / file) - no rekey in window (PFS unknown)."""
    wr = Writer(out)
    hub = "203.0.113.1"
    spokes = [("10.1.0.2", "video", "aead_16"), ("10.2.0.2", "chat", "aead_16"), ("10.3.0.2", "file", "aes_cbc_sha1")]
    ts = T0
    for i, (sp, cls, framing) in enumerate(spokes):
        prop = IKE_GCM128_MODP2048 if framing == "aead_16" else IKE_CBC128_SHA1_MODP2048
        p = IKEv2Peer(wr, sp, hub, ike_encr=("aead", 8, 16, 4) if framing == "aead_16" else ("cbc", 16, 16, 16))
        t = p.sa_init(ts + i * 0.7, [prop], [prop], (14, 256), notifies_i=[N_FRAG, N_SIGHASH], notifies_r=[N_FRAG, N_SIGHASH])
        t = p.ike_auth(t, 12 + 8 + 256 + 40 + 24 + 24, 12 + 8 + 256 + 40 + 24 + 24)
        dur = {"video": 25, "chat": 90, "file": 6}[cls]
        write_esp_traffic(wr, sp, hub, simulate(cls, dur, seed + i), framing, "tunnel", 4, t + 0.5)
    wr.close()
    return {"ike_version": 2, "ike": "AES_GCM_16-128 / MODP-2048 (x2) and AES_CBC-128 / SHA1 / MODP-2048 (x1)", "esp_framing": "o24_b4 (x2), o28_b16 (x1)",
            "esp": "AES-GCM-16 (x2), AES-CBC + HMAC-SHA1-96 (x1)", "mode": "tunnel", "traffic": "video, chat, file", "pfs": "unknown", "ipver": 4,
            "expected_grade": ["B", "C"], "description": "Hub-and-spoke: three tunnels carrying video streaming, WhatsApp-like chat and a bulk file download; one spoke still uses AES-CBC + SHA-1. No rekey in the window, so PFS is honestly reported as Unknown."}


SCENARIOS = {
    "good_ikev2_gcm_pqc_pfs": scen_good,
    "enterprise_cbc_sha256_natt": scen_enterprise,
    "legacy_ikev1_aggressive_3des": scen_legacy_v1,
    "terrible_ikev1_des_md5_null_esp": scen_terrible_v1,
    "ipv6_natt_chacha_transport": scen_ipv6_natt_chacha,
    "ah_only_no_confidentiality": scen_ah_only,
    "replay_flood_anomalies": scen_replay_anomaly,
    "hub_three_spokes_mixed_traffic": scen_hub,
}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "samples"))
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--only", default=None)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    random.seed(args.seed)
    manifest = {}
    mpath = os.path.join(args.out, "manifest.json")
    if os.path.exists(mpath):
        with open(mpath) as f:
            manifest = json.load(f)
    for name, fn in SCENARIOS.items():
        if args.only and name != args.only:
            continue
        path = os.path.join(args.out, name + ".pcap")
        t0 = time.time()
        truth = fn(path, args.seed)
        truth["file"] = name + ".pcap"
        truth["size_bytes"] = os.path.getsize(path)
        manifest[name] = truth
        print(f"  {name:40s} {truth['size_bytes'] / 1e6:6.2f} MB  ({time.time() - t0:.1f}s)")
    with open(mpath, "w") as f:
        json.dump(manifest, f, indent=2)
    print("manifest ->", mpath)


if __name__ == "__main__":
    main()
