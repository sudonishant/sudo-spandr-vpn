"""PCAP / PCAPNG reader producing light-weight packet records (Scapy is used only for link/IP/UDP decoding)."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Iterator, Optional

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import PcapReader, Ether, IP, IPv6, UDP, TCP, ICMP, Raw  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply  # noqa: E402
from scapy.layers.l2 import CookedLinux  # noqa: E402

try:
    from scapy.layers.ipsec import ESP as ScapyESP, AH as ScapyAH  # noqa: E402
except Exception:  # pragma: no cover
    ScapyESP = ScapyAH = None


@dataclass
class PacketRecord:
    index: int
    ts: float
    ipver: int
    src: str
    dst: str
    proto: int                 # IP protocol / next header
    sport: Optional[int]
    dport: Optional[int]
    ip_len: int                # IP total length (v4) or payload+40 (v6)
    frame_len: int
    payload: bytes             # transport payload (UDP payload, or raw ESP/AH bytes)
    fragment: bool = False
    ttl: Optional[int] = None
    l4_len: int = 0            # transport payload length according to the IP header (survives snaplen truncation)


def _ip_layer(pkt):
    if IP in pkt:
        return pkt[IP], 4
    if IPv6 in pkt:
        return pkt[IPv6], 6
    return None, 0


def record_from_packet(pkt, idx: int, ts: Optional[float] = None) -> Optional[PacketRecord]:
    """Convert a decoded scapy packet into a PacketRecord (None for non-IP frames)."""
    ip, ver = _ip_layer(pkt)
    if ip is None:
        return None
    ts = float(pkt.time) if ts is None else ts
    frame_len = len(pkt)
    if ver == 4:
        proto = int(ip.proto)
        ip_len = int(ip.len) if ip.len is not None else len(ip)
        frag = bool(ip.flags & 1) or int(ip.frag) > 0
        ttl = int(ip.ttl)
        l4 = ip_len - int(ip.ihl or 5) * 4
    else:
        proto = int(ip.nh)
        ip_len = int(ip.plen) + 40 if ip.plen is not None else len(ip)
        frag = False
        ttl = int(ip.hlim)
        l4 = ip_len - 40
    sport = dport = None
    if proto == 17 and UDP in pkt:
        u = pkt[UDP]
        sport, dport = int(u.sport), int(u.dport)
        payload = bytes(u.payload)
        l4 -= 8
    elif proto == 6 and TCP in pkt:
        t = pkt[TCP]
        sport, dport = int(t.sport), int(t.dport)
        payload = bytes(t.payload)
    else:
        payload = bytes(ip.payload)
    return PacketRecord(idx, ts, ver, str(ip.src), str(ip.dst), proto, sport, dport, ip_len, frame_len, payload, frag, ttl, max(l4, 0))


def iter_packets(path: str, limit: Optional[int] = None) -> Iterator[PacketRecord]:
    idx = 0
    with PcapReader(path) as rd:
        for pkt in rd:
            idx += 1
            if limit and idx > limit:
                break
            rec = record_from_packet(pkt, idx)
            if rec is not None:
                yield rec


class PcapWriter:
    """Minimal dependency-free pcap (libpcap format) writer for saving live captures."""

    def __init__(self, path: str, linktype: int = 1, snaplen: int = 262144):
        import struct
        self._struct = struct
        self.fh = open(path, "wb")
        self.fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        self.count = 0

    def write(self, ts: float, data: bytes) -> None:
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self.fh.write(self._struct.pack("<IIII", sec, usec, len(data), len(data)))
        self.fh.write(data)
        self.count += 1

    def close(self) -> None:
        self.fh.close()


def read_packets(path: str, limit: Optional[int] = None) -> list[PacketRecord]:
    return list(iter_packets(path, limit))
