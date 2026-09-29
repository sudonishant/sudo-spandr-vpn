"""Put real IPsec packets on the wire (loopback by default) so a *genuine* live capture can be demonstrated
without two VPN gateways: every frame of a sample/any pcap is re-addressed into 127.0.0.0/8 (or the
addresses you choose) and transmitted with the original timing.

    sudo python -m ipsec_xray.testbed.emit --sample enterprise_cbc_sha256_natt --speed 2 --loop
    sudo python -m ipsec_xray.testbed.emit --pcap capture.pcap --iface lo

With root the frames are injected at layer 2 (IPv4 *and* IPv6, raw ESP/AH included). Without root a UDP
fallback is used: IKE and ESP are sent as UDP/4500 NAT-T datagrams between 127.0.0.x addresses (raw ESP/AH
and IPv6 cannot be emitted unprivileged) - enough for a live IKE + ESP demo when only the capture side is
privileged.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.environ.get("IPSEC_XRAY_SAMPLES", os.path.join(ROOT, "samples"))


class AddrMap:
    """Deterministic mapping of the pcap's addresses to loopback addresses (127.0.0.11, .12, ...)."""

    def __init__(self, base: str = "127.0.0."):
        self.base, self.next, self.map = base, 11, {}

    def __call__(self, addr: str) -> str:
        if addr not in self.map:
            self.map[addr] = f"{self.base}{self.next}"
            self.next += 1
        return self.map[addr]


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def emit_l2(path: str, iface: str, speed: float, loop: bool, amap: AddrMap, quiet: bool) -> int:
    from scapy.all import conf
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.utils import PcapReader
    sock = conf.L2socket(iface=iface)
    sent = 0
    while True:
        base_pcap = None
        base_wall = time.time()
        with PcapReader(path) as rd:
            for pkt in rd:
                t = float(pkt.time)
                if base_pcap is None:
                    base_pcap = t
                delay = base_wall + (t - base_pcap) / speed - time.time()
                if delay > 0:
                    time.sleep(delay)
                if IP in pkt:
                    ip = pkt[IP]
                    ip.src, ip.dst = amap(ip.src), amap(ip.dst)
                    del ip.chksum
                    if UDP in ip:
                        del ip[UDP].chksum
                    frame = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00") / ip
                elif IPv6 in pkt:
                    frame = Ether(src="00:00:00:00:00:00", dst="00:00:00:00:00:00") / pkt[IPv6]   # ::1-style rewrite not needed on lo
                else:
                    continue
                sock.send(frame)
                sent += 1
                if not quiet and sent % 500 == 0:
                    print(f"[emit] {sent} frames", flush=True)
        if not loop:
            break
    return sent


def emit_udp(path: str, speed: float, loop: bool, amap: AddrMap, quiet: bool) -> int:
    """Unprivileged fallback: UDP/4500 NAT-T datagrams between distinct loopback addresses."""
    from scapy.layers.inet import IP, UDP
    from scapy.utils import PcapReader
    socks: dict[tuple[str, int], socket.socket] = {}

    def sock_for(src: str, port: int) -> socket.socket:
        key = (src, port)
        if key not in socks:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.bind((src, port))
            except OSError:            # privileged port or busy: ephemeral
                s.bind((src, 0))
            socks[key] = s
        return socks[key]

    sent = skipped = 0
    while True:
        base_pcap = None
        base_wall = time.time()
        with PcapReader(path) as rd:
            for pkt in rd:
                t = float(pkt.time)
                if base_pcap is None:
                    base_pcap = t
                delay = base_wall + (t - base_pcap) / speed - time.time()
                if delay > 0:
                    time.sleep(delay)
                if IP not in pkt:
                    skipped += 1
                    continue
                ip = pkt[IP]
                src, dst = amap(ip.src), amap(ip.dst)
                if ip.proto == 17 and UDP in ip:
                    u = ip[UDP]
                    payload = bytes(u.payload)
                    if u.dport == 500 or u.sport == 500:
                        payload = b"\x00\x00\x00\x00" + payload      # IKE -> NAT-T framing on 4500
                    elif not (u.dport == 4500 or u.sport == 4500):
                        sock_for(src, u.sport).sendto(payload, (dst, u.dport))
                        sent += 1
                        continue
                    sock_for(src, 4500).sendto(payload, (dst, 4500))
                    sent += 1
                elif ip.proto == 50:
                    sock_for(src, 4500).sendto(bytes(ip.payload), (dst, 4500))   # raw ESP -> UDP-encapsulated ESP
                    sent += 1
                else:
                    skipped += 1
                if not quiet and sent % 500 == 0 and sent:
                    print(f"[emit] {sent} datagrams ({skipped} skipped)", flush=True)
        if not loop:
            break
    return sent


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ipsec-xray-emit", description="Transmit a pcap's IPsec traffic on a local interface for live-capture demos.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sample", help="sample name from samples/manifest.json")
    g.add_argument("--pcap", help="any pcap file")
    ap.add_argument("--iface", default="lo", help="interface to inject on (root mode), default lo")
    ap.add_argument("--speed", type=float, default=1.0)
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--udp", action="store_true", help="force the unprivileged UDP/4500 fallback")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    if a.sample:
        with open(os.path.join(SAMPLES, "manifest.json")) as f:
            man = json.load(f)
        if a.sample not in man:
            print(f"unknown sample {a.sample}; available: {', '.join(man)}", file=sys.stderr)
            return 2
        path = os.path.join(SAMPLES, man[a.sample].get("file", a.sample + ".pcap"))
    else:
        path = a.pcap
    amap = AddrMap()
    t0 = time.time()
    try:
        if _is_root() and not a.udp:
            print(f"[emit] root: injecting {os.path.basename(path)} on {a.iface} at {a.speed}x (addresses -> 127.0.0.x)", flush=True)
            n = emit_l2(path, a.iface, a.speed, a.loop, amap, a.quiet)
        else:
            print(f"[emit] unprivileged: UDP/4500 NAT-T fallback on loopback at {a.speed}x (raw ESP/AH and IPv6 need root)", flush=True)
            n = emit_udp(path, a.speed, a.loop, amap, a.quiet)
    except KeyboardInterrupt:
        n = -1
    print(f"[emit] done in {time.time() - t0:.1f}s; address map: {amap.map}", flush=True)
    return 0 if n else 1


if __name__ == "__main__":
    sys.exit(main())
