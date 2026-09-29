"""Capture agent: sniff an interface (or replay a pcap) on any machine and stream the frames to an IPsec X-Ray
server over WebSocket, so the analysis + UI can run somewhere else (a laptop, a server, a phone browser).

    sudo python -m ipsec_xray.live.agent --server http://192.168.1.10:8000 --iface eth0
    sudo python -m ipsec_xray.live.agent --server http://localhost:8000 --iface lo --ipsec-only
    python      -m ipsec_xray.live.agent --server http://localhost:8000 --pcap samples/enterprise_cbc_sha256_natt.pcap --speed 5

Wire format (binary WebSocket messages, several frames per message):
    struct '!dII' = (timestamp, linktype, length) followed by the raw frame bytes.
Only the raw sockets live here - the agent never analyses anything, so it stays tiny and dependency-light
(scapy + websockets). Root / CAP_NET_RAW / Npcap is needed for interface capture, not for pcap replay.
"""
from __future__ import annotations

import argparse
import struct
import sys
import threading
import time
from urllib.parse import quote

from .sources import LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW_IP, list_interfaces

IPSEC_PORTS = {500, 4500}


def _is_ipsec(pkt) -> bool:
    from scapy.layers.inet import IP, UDP
    from scapy.layers.inet6 import IPv6
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return False
    proto = ip.proto if isinstance(ip, IP) else ip.nh
    if proto in (50, 51):
        return True
    if proto == 17 and pkt.haslayer(UDP):
        u = pkt[UDP]
        return u.sport in IPSEC_PORTS or u.dport in IPSEC_PORTS
    return False


class Uplink:
    """Batches frames and pushes them over a (re)connecting WebSocket."""

    def __init__(self, server: str, name: str, iface: str, profile: str, verbose: bool = True):
        base = server.rstrip("/")
        if base.startswith("http://"):
            base = "ws://" + base[7:]
        elif base.startswith("https://"):
            base = "wss://" + base[8:]
        elif not base.startswith(("ws://", "wss://")):
            base = "ws://" + base
        self.url = f"{base}/ws/agent?name={quote(name)}&iface={quote(iface)}&profile={quote(profile)}"
        self.verbose = verbose
        self.lock = threading.Lock()
        self.buf = bytearray()
        self.frames_buffered = 0
        self.sent_frames = 0
        self.sent_bytes = 0
        self.dropped = 0
        self.connected = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)

    def push(self, ts: float, linktype: int, raw: bytes) -> None:
        with self.lock:
            if len(self.buf) > 8 * 1024 * 1024:      # uplink down for a while: drop instead of eating RAM
                self.dropped += 1
                return
            self.buf += struct.pack("!dII", ts, linktype, len(raw)) + raw
            self.frames_buffered += 1

    def _take(self) -> tuple[bytes, int]:
        with self.lock:
            if not self.buf:
                return b"", 0
            data, n = bytes(self.buf), self.frames_buffered
            self.buf = bytearray()
            self.frames_buffered = 0
            return data, n

    def _run(self) -> None:
        from websockets.sync.client import connect
        backoff = 1.0
        while not self._stop.is_set():
            try:
                with connect(self.url, max_size=None, open_timeout=10) as ws:
                    self.connected = True
                    backoff = 1.0
                    if self.verbose:
                        print(f"[agent] connected to {self.url}", flush=True)
                    last_report = time.time()
                    while not self._stop.is_set():
                        data, n = self._take()
                        if data:
                            ws.send(data)
                            self.sent_frames += n
                            self.sent_bytes += len(data)
                        else:
                            time.sleep(0.05)
                        if self.verbose and time.time() - last_report >= 5:
                            print(f"[agent] sent {self.sent_frames} frames / {self.sent_bytes / 1024:.0f} KiB"
                                  + (f" (dropped {self.dropped})" if self.dropped else ""), flush=True)
                            last_report = time.time()
                    data, n = self._take()
                    if data:
                        ws.send(data)
            except Exception as e:
                self.connected = False
                if self.verbose:
                    print(f"[agent] uplink error: {type(e).__name__}: {e} - retrying in {backoff:.0f}s", flush=True)
                if self._stop.wait(backoff):
                    break
                backoff = min(backoff * 2, 15)
        self.connected = False


def run_interface(up: Uplink, iface: str, ipsec_only: bool, bpf: str | None, stop: threading.Event) -> None:
    from .sources import capture, decode_frame
    seen = [0]

    def on_frame(ts: float, lt: int, raw: bytes) -> None:
        if ipsec_only and not _is_ipsec(decode_frame(lt, raw)):
            return
        seen[0] += 1
        up.push(ts, lt, raw)

    if bpf:
        print("[agent] note: --bpf is ignored by the native capture loop; use --ipsec-only to reduce traffic", flush=True)
    print(f"[agent] capturing on {iface}" + (" (IPsec traffic only)" if ipsec_only else "") + " - Ctrl+C to stop", flush=True)
    try:
        capture(iface, stop, on_frame)
    except PermissionError:
        raise SystemExit(f"[agent] cannot capture on {iface}: permission denied (run with sudo / as Administrator with Npcap)")
    except OSError as e:
        raise SystemExit(f"[agent] cannot capture on {iface}: {e}")


def run_pcap(up: Uplink, path: str, speed: float, loop: bool, stop: threading.Event) -> None:
    from scapy.utils import PcapReader
    print(f"[agent] replaying {path} at {speed}x" + (" (loop)" if loop else ""), flush=True)
    while not stop.is_set():
        base_pcap = None
        base_wall = time.time()
        with PcapReader(path) as rd:
            lt = getattr(rd, "linktype", LINKTYPE_ETHERNET) or LINKTYPE_ETHERNET
            for pkt in rd:
                if stop.is_set():
                    return
                t = float(pkt.time)
                if base_pcap is None:
                    base_pcap = t
                delay = base_wall + (t - base_pcap) / speed - time.time()
                while delay > 0 and not stop.is_set():
                    time.sleep(min(delay, 0.2))
                    delay = base_wall + (t - base_pcap) / speed - time.time()
                up.push(time.time(), lt, bytes(pkt))
        if not loop:
            break
    # let the uplink drain
    time.sleep(1.0)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ipsec-xray-agent", description="Stream packets from this machine to an IPsec X-Ray server for live analysis.")
    ap.add_argument("--server", default="http://localhost:8000", help="IPsec X-Ray server URL (http[s]://host:port)")
    ap.add_argument("--iface", help="interface to capture (needs root / CAP_NET_RAW / Npcap)")
    ap.add_argument("--pcap", help="replay this pcap instead of capturing")
    ap.add_argument("--speed", type=float, default=1.0, help="replay speed factor (with --pcap)")
    ap.add_argument("--loop", action="store_true", help="loop the replay (with --pcap)")
    ap.add_argument("--name", default=None, help="agent name shown in the UI (default: hostname)")
    ap.add_argument("--profile", default="baseline", help="assessment profile to start the live session with")
    ap.add_argument("--ipsec-only", action="store_true", help="send only IKE/ESP/AH/NAT-T frames (saves bandwidth)")
    ap.add_argument("--bpf", default=None, help=argparse.SUPPRESS)
    ap.add_argument("--list", action="store_true", help="list interfaces and exit")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args(argv)
    if a.list:
        for i in list_interfaces():
            print(f"{i['name']:<16} {i['state']}")
        return 0
    if not a.iface and not a.pcap:
        ap.error("give --iface <name> or --pcap <file> (or --list)")
    import socket
    name = a.name or socket.gethostname()
    up = Uplink(a.server, name, a.iface or f"pcap:{a.pcap}", a.profile, verbose=not a.quiet)
    up.start()
    stop = threading.Event()
    try:
        if a.pcap:
            run_pcap(up, a.pcap, a.speed, a.loop, stop)
        else:
            run_interface(up, a.iface, a.ipsec_only, a.bpf, stop)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        up.stop()
        print(f"[agent] done - {up.sent_frames} frames sent", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
