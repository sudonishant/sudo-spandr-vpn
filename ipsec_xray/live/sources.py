"""Packet sources for live mode.

Every source runs in its own thread and calls ``sink(ts, linktype, raw_bytes, scapy_pkt)`` for each frame.

* InterfaceSource  - sniff a local network interface (needs CAP_NET_RAW / root / Npcap on Windows)
* ReplaySource     - replay a pcap file with the original timing (speed factor, optional loop); timestamps
                     are re-based to "now" so the UI behaves exactly as with a live interface
* AgentSource      - frames pushed by a remote capture agent over WebSocket (see ipsec_xray.live.agent)
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Optional

Sink = Callable[[float, int, bytes, object], None]

LINKTYPE_ETHERNET = 1
LINKTYPE_RAW_IP = 101
LINKTYPE_LINUX_SLL = 113
LINKTYPE_NULL = 0


def list_interfaces() -> list[dict]:
    """Interfaces visible to this host (Linux /sys, else scapy)."""
    out = []
    try:
        for name in sorted(os.listdir("/sys/class/net")):
            try:
                with open(f"/sys/class/net/{name}/operstate") as f:
                    state = f.read().strip()
            except OSError:
                state = "unknown"
            out.append({"name": name, "state": state})
    except OSError:
        try:
            from scapy.all import get_if_list
            out = [{"name": n, "state": "unknown"} for n in get_if_list()]
        except Exception:
            out = []
    return out


def can_sniff() -> tuple[bool, str]:
    """Whether this process may open a raw capture socket."""
    try:
        import socket
        if os.name == "nt":
            return True, "windows (needs Npcap)"
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)  # type: ignore[attr-defined]
        s.close()
        return True, "raw sockets available"
    except PermissionError:
        return False, "no CAP_NET_RAW - run the capture agent with sudo, or replay a pcap"
    except Exception as e:  # pragma: no cover
        return False, str(e)


def decode_frame(linktype: int, raw: bytes):
    """Raw bytes -> scapy packet for the given pcap linktype (falls back to Raw)."""
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Raw
    try:
        if linktype == LINKTYPE_RAW_IP:
            return IP(raw) if raw and raw[0] >> 4 == 4 else IPv6(raw)
        if linktype == LINKTYPE_LINUX_SLL:
            from scapy.layers.l2 import CookedLinux
            return CookedLinux(raw)
        return Ether(raw)
    except Exception:
        return Raw(raw)


def linux_capture(iface: str, stop: threading.Event, on_frame: Callable[[float, int, bytes], None]) -> None:
    """Minimal AF_PACKET capture loop (Linux). Unlike a plain scapy sniff it drops the *outgoing* copy of every
    loopback frame - exactly what libpcap does - so traffic on ``lo`` is not counted twice. Raises PermissionError
    without CAP_NET_RAW."""
    import select
    import socket
    ETH_P_ALL = 0x0003
    PACKET_OUTGOING = 4
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))  # type: ignore[attr-defined]
    try:
        s.bind((iface, 0))
        try:
            with open(f"/sys/class/net/{iface}/type") as f:
                hatype = int(f.read().strip())
        except OSError:
            hatype = 1
        loopback = hatype == 772
        linktype = LINKTYPE_ETHERNET if hatype in (1, 772) else LINKTYPE_RAW_IP
        s.setblocking(False)
        while not stop.is_set():
            r, _, _ = select.select([s], [], [], 0.25)
            if not r:
                continue
            try:
                data, sa = s.recvfrom(262144)
            except BlockingIOError:
                continue
            if loopback and sa[2] == PACKET_OUTGOING:
                continue
            on_frame(time.time(), linktype, data)
    finally:
        s.close()


def capture(iface: str, stop: threading.Event, on_frame: Callable[[float, int, bytes], None]) -> None:
    """Capture frames from an interface until ``stop`` is set: native AF_PACKET loop on Linux, scapy elsewhere."""
    import sys
    if sys.platform.startswith("linux"):
        linux_capture(iface, stop, on_frame)
        return
    from scapy.all import AsyncSniffer, conf
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    conf.sniff_promisc = 1

    def prn(pkt):
        if stop.is_set():
            return
        if isinstance(pkt, Ether):
            lt = LINKTYPE_ETHERNET
        elif isinstance(pkt, (IP, IPv6)):
            lt = LINKTYPE_RAW_IP
        else:
            lt = LINKTYPE_LINUX_SLL if pkt.__class__.__name__ == "CookedLinux" else LINKTYPE_ETHERNET
        on_frame(float(pkt.time), lt, bytes(pkt))

    sniffer = AsyncSniffer(iface=iface, prn=prn, store=False)
    sniffer.start()
    time.sleep(0.3)
    if not sniffer.running:
        exc = getattr(sniffer, "exception", None)
        raise RuntimeError(f"cannot sniff on {iface}: {exc or 'permission denied or no such interface'}")
    try:
        while not stop.is_set():
            time.sleep(0.2)
            if not sniffer.running:
                exc = getattr(sniffer, "exception", None)
                if exc:
                    raise RuntimeError(f"sniffer stopped: {exc}")
                break
    finally:
        try:
            sniffer.stop(join=False)
        except Exception:
            pass


class BaseSource:
    kind = "base"

    def __init__(self, sink: Sink):
        self.sink = sink
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.error: Optional[str] = None
        self.frames = 0
        self.started_at: Optional[float] = None

    def start(self) -> None:
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._guarded_run, name=f"source-{self.kind}", daemon=True)
        self._thread.start()

    def _guarded_run(self) -> None:
        try:
            self.run()
        except Exception as e:  # surface the reason in the UI instead of dying silently
            self.error = f"{type(e).__name__}: {e}"

    def run(self) -> None:  # pragma: no cover - abstract
        raise NotImplementedError

    def stop(self) -> None:
        self._stop.set()

    @property
    def alive(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def describe(self) -> dict:
        return {"kind": self.kind, "frames": self.frames, "error": self.error, "alive": self.alive}

    def emit(self, ts: float, linktype: int, raw: bytes, pkt) -> None:
        self.frames += 1
        self.sink(ts, linktype, raw, pkt)


class InterfaceSource(BaseSource):
    kind = "interface"

    def __init__(self, sink: Sink, iface: str):
        super().__init__(sink)
        self.iface = iface

    def run(self) -> None:
        def on_frame(ts: float, lt: int, raw: bytes) -> None:
            self.emit(ts, lt, raw, decode_frame(lt, raw))
        try:
            capture(self.iface, self._stop, on_frame)
        except PermissionError:
            raise RuntimeError(f"cannot sniff on {self.iface}: no CAP_NET_RAW (run the capture agent with sudo)")

    def describe(self) -> dict:
        d = super().describe()
        d["iface"] = self.iface
        return d


class ReplaySource(BaseSource):
    kind = "replay"

    def __init__(self, sink: Sink, path: str, speed: float = 1.0, loop: bool = False, label: str | None = None):
        super().__init__(sink)
        self.path, self.speed, self.loop = path, max(0.05, float(speed)), loop
        self.label = label or os.path.basename(path)
        self.progress = 0.0
        self.total_frames = 0
        self.linktype = LINKTYPE_ETHERNET

    def run(self) -> None:
        from scapy.utils import PcapReader
        # count frames once so the UI can show progress
        with PcapReader(self.path) as rd:
            self.linktype = getattr(rd, "linktype", LINKTYPE_ETHERNET) or LINKTYPE_ETHERNET
            for _ in rd:
                self.total_frames += 1
        while not self._stop.is_set():
            base_pcap = None
            base_wall = time.time()
            with PcapReader(self.path) as rd:
                for i, pkt in enumerate(rd):
                    if self._stop.is_set():
                        return
                    t = float(pkt.time)
                    if base_pcap is None:
                        base_pcap = t
                    target = base_wall + (t - base_pcap) / self.speed
                    delay = target - time.time()
                    if delay > 0:
                        # sleep in short slices so stop() stays responsive
                        while delay > 0 and not self._stop.is_set():
                            time.sleep(min(delay, 0.2))
                            delay = target - time.time()
                    # timestamps keep the capture's *real* spacing (re-based to the start of the replay) even when the
                    # frames are pushed faster: rates, lifetimes and timing features stay truthful at any speed
                    ts = base_wall + (t - base_pcap)
                    pkt.time = ts
                    self.progress = (i + 1) / max(1, self.total_frames)
                    self.emit(ts, self.linktype, bytes(pkt), pkt)
            if not self.loop:
                break

    def describe(self) -> dict:
        d = super().describe()
        d.update({"file": self.label, "speed": self.speed, "loop": self.loop, "progress": round(self.progress, 3), "total_frames": self.total_frames})
        return d


class AgentSource(BaseSource):
    """Frames arrive from ``ipsec_xray.live.agent`` over the /ws/agent WebSocket; the API pushes them in."""
    kind = "agent"

    def __init__(self, sink: Sink, agent_name: str, iface: str):
        super().__init__(sink)
        self.agent_name, self.iface = agent_name, iface
        self.last_seen = time.time()

    def run(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.5)

    def push(self, ts: float, linktype: int, raw: bytes) -> None:
        self.last_seen = time.time()
        self.emit(ts, linktype, raw, decode_frame(linktype, raw))

    def describe(self) -> dict:
        d = super().describe()
        d.update({"agent": self.agent_name, "iface": self.iface, "last_seen": round(time.time() - self.last_seen, 1)})
        return d
