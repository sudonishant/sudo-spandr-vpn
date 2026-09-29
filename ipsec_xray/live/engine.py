"""Incremental live analyzer: packets in, Wireshark-style rows + rolling assessment + alerts out."""
from __future__ import annotations

import binascii
import os
import struct
import threading
import time
from collections import Counter, deque
from typing import Callable, Optional

from ..analysis.inference import build_facts
from ..analysis.session import SessionBuilder
from ..assessment.engine import assess
from ..pcap.reader import PacketRecord, PcapWriter, record_from_packet
from ..protocols import registry as R
from ..protocols.esp import parse_ah, parse_esp
from ..protocols.ike import parse_ike
from .sources import AgentSource, BaseSource, InterfaceSource, ReplaySource

Listener = Callable[[dict], None]

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP"}
ALERT_SEVERITIES = ("critical", "high", "medium")


def _hexdump(data: bytes, limit: int = 256) -> list[str]:
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hx:<47}  {asc}")
    if len(data) > limit:
        lines.append(f"... {len(data) - limit} more bytes")
    return lines


class LiveAnalyzer:
    """One live session: a packet source feeds frames; the analyzer keeps a bounded packet list for the UI,
    an incremental protocol session and a periodically refreshed facts+assessment snapshot."""

    def __init__(self, profile: str = "baseline", snapshot_interval: float = 2.0, ring: int = 4000, keep_frames: int = 250_000):
        self.profile = profile
        self.snapshot_interval = snapshot_interval
        self.lock = threading.RLock()
        self.listeners: list[Listener] = []
        self.rows: deque = deque(maxlen=ring)
        self.frames: deque = deque(maxlen=keep_frames)      # (index, ts, linktype, raw)
        self.pending_rows: list[dict] = []
        self.builder = SessionBuilder()
        self.index = 0
        self.t0: Optional[float] = None
        self.counts = Counter()
        self.bytes = Counter()
        self.buckets: deque = deque(maxlen=180)              # per-second: {"t", "pkts", "bytes", "ike", "esp", "ah", "other"}
        self.alerts: deque = deque(maxlen=300)
        self.seen_findings: set = set()
        self.seen_ike: set = set()
        self.seen_tunnels: set = set()
        self._primed = True
        self.snapshot: Optional[dict] = None
        self.snapshot_at: float = 0.0
        self.snapshot_ms: float = 0.0
        self.source: Optional[BaseSource] = None
        self.running = False
        self.started_at: Optional[float] = None
        self.stopped_at: Optional[float] = None
        self._worker: Optional[threading.Thread] = None
        self._dirty = False

    # ------------------------------------------------------------------ lifecycle
    def start(self, source: BaseSource) -> None:
        with self.lock:
            if self.running:
                raise RuntimeError("already running")
            self.source = source
            self.running = True
            self.started_at = time.time()
            self.stopped_at = None
        from ..ml.models import Models
        Models.get()   # load the classifiers now so the first snapshot is not delayed
        source.start()
        self._worker = threading.Thread(target=self._loop, name="live-analyzer", daemon=True)
        self._worker.start()
        self._publish({"type": "status", **self.status()})
        self._alert("info", "LIVE", f"capture started ({source.describe().get('kind')})", "", "")

    def stop(self) -> None:
        with self.lock:
            if not self.running:
                return
            self.running = False
            self.stopped_at = time.time()
        if self.source:
            self.source.stop()
        if self._worker:
            self._worker.join(timeout=3)
        self._refresh_snapshot(force=True)
        self._publish({"type": "status", **self.status()})
        self._alert("info", "LIVE", "capture stopped", "", "")

    def reset(self) -> None:
        self.stop()
        with self.lock:
            self.rows.clear(); self.frames.clear(); self.pending_rows.clear()
            self.builder = SessionBuilder()
            self.index = 0; self.t0 = None
            self.counts = Counter(); self.bytes = Counter(); self.buckets.clear()
            self.alerts.clear(); self.seen_findings.clear(); self.seen_ike.clear(); self.seen_tunnels.clear()
            self.snapshot = None; self.snapshot_at = 0.0
            self.source = None
        self._publish({"type": "status", **self.status()})
        self._publish({"type": "reset"})

    # ------------------------------------------------------------------ input
    def on_frame(self, ts: float, linktype: int, raw: bytes, pkt) -> None:
        with self.lock:
            self.index += 1
            idx = self.index
            if self.t0 is None:
                self.t0 = ts
            self.frames.append((idx, ts, linktype, raw))
            rec = record_from_packet(pkt, idx, ts)
            if rec is None:
                kind, row = "other", self._row_generic(idx, ts, None, raw, pkt)
            else:
                kind = self.builder.feed(rec)
                row = self._row(idx, ts, rec, kind)
            self.counts[kind] += 1
            self.counts["total"] += 1
            self.bytes["total"] += len(raw)
            self.bytes[kind] += len(raw)
            sec = int(time.time())          # rate charts follow arrival time (= ts on a live interface)
            if not self.buckets or self.buckets[-1]["t"] != sec:
                self.buckets.append({"t": sec, "pkts": 0, "bytes": 0, "ike": 0, "esp": 0, "ah": 0, "other": 0})
            b = self.buckets[-1]
            b["pkts"] += 1
            b["bytes"] += len(raw)
            b[kind if kind in ("ike", "esp", "ah") else "other"] += 1
            self.rows.append(row)
            self.pending_rows.append(row)
            self._dirty = True

    def _row(self, idx: int, ts: float, rec: PacketRecord, kind: str) -> dict:
        proto = PROTO_NAMES.get(rec.proto, f"IP/{rec.proto}")
        info = ""
        color = "other"
        if kind == "ike":
            payload = rec.payload[4:] if 4500 in (rec.sport, rec.dport) else rec.payload
            msg = parse_ike(payload)
            if msg:
                proto = f"IKEv{msg.version}"
                color = "ike"
                flags = "response" if msg.response else "request"
                extra = []
                if msg.proposals:
                    extra.append(f"SA({len(msg.proposals)} prop)")
                if msg.ke_group is not None:
                    extra.append(f"KE {R.dh_name(msg.ke_group)}")
                for n in msg.notify_names()[:4]:
                    extra.append(f"N({n})")
                if msg.sk_len:
                    extra.append(f"SK {msg.sk_len} B")
                if msg.ids:
                    extra.append("ID " + ", ".join(i.get("value", "") for i in msg.ids[:2]))
                info = f"{msg.exchange_name} {flags} #{msg.msg_id} " + " ".join(extra)
                if msg.version == 1 and msg.exchange == 4:
                    color = "warn"
                if msg.errors:
                    color = "bad"
                    info += " [malformed]"
        elif kind == "esp":
            payload = rec.payload if rec.proto == 50 else rec.payload
            esp = parse_esp(payload)
            proto = "ESP" + ("/UDP" if rec.proto == 17 else "")
            color = "esp"
            if esp:
                info = f"SPI 0x{esp.spi:08x}  seq {esp.seq}  len {esp.total_len}"
        elif kind == "ah":
            ah = parse_ah(rec.payload)
            proto, color = "AH", "ah"
            if ah:
                info = f"SPI 0x{ah.spi:08x}  seq {ah.seq}  ICV {ah.icv_len} B  next {PROTO_NAMES.get(ah.next_header, ah.next_header)}"
        elif kind == "keepalive":
            proto, color, info = "NAT-KA", "ka", "NAT-T keepalive"
        else:
            if rec.proto in (6, 17):
                info = f"{rec.sport} → {rec.dport}  {len(rec.payload)} B"
                if rec.proto == 6 and 4500 in (rec.sport, rec.dport):
                    info += "  (TCP encapsulation?)"
            elif rec.proto in (1, 58):
                t = rec.payload[0] if rec.payload else -1
                info = {8: "echo request", 0: "echo reply", 128: "echo request", 129: "echo reply", 3: "unreachable", 11: "time exceeded"}.get(t, f"type {t}")
        return {"n": idx, "t": round(ts - (self.t0 or ts), 6), "ts": ts, "src": rec.src, "dst": rec.dst, "proto": proto,
                "len": rec.frame_len, "info": info, "c": color, "ipv": rec.ipver}

    def _row_generic(self, idx: int, ts: float, rec, raw: bytes, pkt) -> dict:
        name = pkt.__class__.__name__ if pkt is not None else "frame"
        last = pkt.lastlayer().__class__.__name__ if pkt is not None else name
        return {"n": idx, "t": round(ts - (self.t0 or ts), 6), "ts": ts, "src": "-", "dst": "-", "proto": last, "len": len(raw),
                "info": f"{name} frame (non-IP)", "c": "other", "ipv": 0}

    # ------------------------------------------------------------------ worker
    def _loop(self) -> None:
        last_flush = last_stats = last_snap = 0.0
        while True:
            time.sleep(0.15)
            now = time.time()
            if self.pending_rows and now - last_flush >= 0.25:
                with self.lock:
                    rows, self.pending_rows = self.pending_rows, []
                self._publish({"type": "packets", "rows": rows[-600:], "dropped": max(0, len(rows) - 600)})
                last_flush = now
            if now - last_stats >= 1.0:
                self._publish({"type": "stats", **self.stats()})
                last_stats = now
                if self.source and (self.source.error or (not self.source.alive and self.source.kind == "replay")):
                    # replay finished or the source died: stop but keep everything on screen
                    err = self.source.error
                    with self.lock:
                        rows, self.pending_rows = self.pending_rows, []
                    if rows:
                        self._publish({"type": "packets", "rows": rows[-400:], "dropped": max(0, len(rows) - 400)})
                    self._refresh_snapshot(force=True)
                    self.running = False
                    self.stopped_at = time.time()
                    self._alert("high" if err else "info", "SOURCE", err or "replay finished - capture complete", "", "")
                    self._publish({"type": "status", **self.status()})
                    return
            if now - last_snap >= max(self.snapshot_interval, 3 * self.snapshot_ms / 1000.0):
                self._refresh_snapshot()
                last_snap = time.time()
            if not self.running:
                with self.lock:
                    rows, self.pending_rows = self.pending_rows, []
                if rows:
                    self._publish({"type": "packets", "rows": rows[-400:], "dropped": max(0, len(rows) - 400)})
                self._publish({"type": "stats", **self.stats()})
                return

    def _refresh_snapshot(self, force: bool = False) -> None:
        if not self._dirty and not force:
            return
        t0 = time.time()
        with self.lock:
            self._dirty = False
            sess = self.builder.finish()
            try:
                facts = build_facts(sess, "live")
            except Exception as e:  # keep the live view alive even if inference trips on a partial session
                self._alert("medium", "ENGINE", f"snapshot failed: {type(e).__name__}: {e}", "", "")
                return
        assessment = assess(facts, self.profile)
        snap = self._trim(facts, assessment)
        snap["computed_in_ms"] = round((time.time() - t0) * 1000, 1)
        self.snapshot, self.snapshot_at, self.snapshot_ms = snap, time.time(), snap["computed_in_ms"]
        self._diff_alerts(assessment, facts)
        self._publish({"type": "snapshot", "snapshot": snap})

    def _trim(self, facts: dict, assessment: dict) -> dict:
        """Snapshot payload for the browser: everything the dashboard needs, minus bulky per-packet logs."""
        ike = []
        for i in facts["ike"]:
            j = {k: v for k, v in i.items() if k not in ("exchange_log", "child_rekeys", "ike_auth_lens", "nonce_lens")}
            j["exchange_log_len"] = len(i.get("exchange_log", []))
            ike.append(j)
        tunnels = []
        for t in facts["tunnels"]:
            u = {k: v for k, v in t.items() if k not in ("flows", "rekeys")}
            u["flows"] = [{k: v for k, v in f.items() if k != "len_hist"} | {"len_hist": dict(sorted(f.get("len_hist", {}).items(), key=lambda kv: -kv[1])[:12])}
                          for f in t.get("flows", [])]
            fr = dict(u.get("framing", {}))
            fr["candidates"] = fr.get("candidates", [])[:6]
            u["framing"] = fr
            tunnels.append(u)
        cap = {k: v for k, v in facts["capture"].items() if k != "model_meta"}
        a = {k: v for k, v in assessment.items() if k != "check_results"}
        a["check_status"] = Counter(c["status"] for c in assessment["check_results"])
        return {"capture": cap, "ike": ike, "tunnels": tunnels, "summary": facts["summary"], "assessment": a, "profile": self.profile}

    def _diff_alerts(self, assessment: dict, facts: dict) -> None:
        for f in assessment["findings"]:
            if f["severity"] not in ALERT_SEVERITIES:
                continue
            key = (f["id"], f["subject"])
            if key in self.seen_findings:
                continue
            self.seen_findings.add(key)
            self._alert(f["severity"], f["id"], f["title"], f["subject"], f["message"], fix=f["fix"], tier=f["tier"], confidence=f["confidence"])
        for i in facts["ike"]:
            if not i["complete"] or i["spi_i"] in self.seen_ike:
                continue
            self.seen_ike.add(i["spi_i"])
            if self._primed:
                mode = f" ({i['v1_mode']} mode)" if i["version"] == 1 and i.get("v1_mode") else ""
                self._alert("info", "IKE", f"IKEv{i['version']} SA established{mode} {i['initiator']} → {i['responder']}: "
                            f"{i['encr_label']} / {i.get('prf') or i.get('integ') or '-'} / {i['dh']}", f"IKEv{i['version']} SA {i['spi_i'][:8]}", "")
        for t in facts["tunnels"]:
            key = (t["protocol"], tuple(t["peers"]))
            if key in self.seen_tunnels:
                continue
            self.seen_tunnels.add(key)
            if self._primed:
                fr = t.get("framing") or {}
                self._alert("info", "TUNNEL", f"{t['protocol']} tunnel {t['peers'][0]} ↔ {t['peers'][1]} detected"
                            + (f" - {fr.get('label')}" if fr.get("label") else ""), "tunnel", "")
        self._primed = True

    def _alert(self, severity: str, code: str, title: str, subject: str, message: str, **extra) -> None:
        a = {"ts": time.time(), "severity": severity, "id": code, "title": title, "subject": subject, "message": message, **extra}
        self.alerts.append(a)
        self._publish({"type": "alert", "alert": a})

    # ------------------------------------------------------------------ output
    def add_listener(self, fn: Listener) -> None:
        self.listeners.append(fn)

    def remove_listener(self, fn: Listener) -> None:
        if fn in self.listeners:
            self.listeners.remove(fn)

    def _publish(self, event: dict) -> None:
        for fn in list(self.listeners):
            try:
                fn(event)
            except Exception:
                pass

    def stats(self) -> dict:
        with self.lock:
            now = time.time()
            recent = [b for b in self.buckets if b["t"] >= int(now) - 10]
            pps = sum(b["pkts"] for b in recent) / 10.0
            bps = sum(b["bytes"] for b in recent) * 8 / 10.0
            return {"counts": dict(self.counts), "bytes": dict(self.bytes), "pps": round(pps, 1), "bps": round(bps),
                    "buckets": list(self.buckets)[-120:], "rows_kept": len(self.rows), "frames_kept": len(self.frames),
                    "uptime": round(now - self.started_at, 1) if self.started_at else 0,
                    "source": self.source.describe() if self.source else None, "packets": self.index, "running": self.running}

    def status(self) -> dict:
        return {"running": self.running, "profile": self.profile, "source": self.source.describe() if self.source else None,
                "started_at": self.started_at, "stopped_at": self.stopped_at, "packets": self.index,
                "snapshot_age": round(time.time() - self.snapshot_at, 1) if self.snapshot_at else None, "snapshot_ms": self.snapshot_ms,
                "alerts": len(self.alerts)}

    def hello(self) -> dict:
        return {"type": "hello", "status": self.status(), "stats": self.stats(), "rows": list(self.rows)[-500:],
                "alerts": list(self.alerts)[-100:], "snapshot": self.snapshot}

    def set_profile(self, profile: str) -> None:
        self.profile = profile
        self.seen_findings.clear()
        self._dirty = True
        self._refresh_snapshot(force=True)

    # ------------------------------------------------------------------ packet detail / save
    def packet_detail(self, n: int) -> Optional[dict]:
        with self.lock:
            hit = next(((i, ts, lt, raw) for (i, ts, lt, raw) in self.frames if i == n), None)
        if hit is None:
            return None
        _, ts, lt, raw = hit
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6
        try:
            pkt = Ether(raw) if lt == 1 else (IP(raw) if raw and raw[0] >> 4 == 4 else IPv6(raw))
        except Exception:
            pkt = None
        rec = record_from_packet(pkt, n, ts) if pkt is not None else None
        tree: list[dict] = [{"name": "Frame", "fields": {"number": n, "time": ts, "length": len(raw), "linktype": lt}}]
        if rec is None:
            tree.append({"name": "Raw", "fields": {"note": "non-IP frame"}})
            return {"n": n, "tree": tree, "hex": _hexdump(raw)}
        tree.append({"name": f"IPv{rec.ipver}", "fields": {"src": rec.src, "dst": rec.dst, "protocol": PROTO_NAMES.get(rec.proto, rec.proto),
                                                          "total_length": rec.ip_len, "ttl/hlim": rec.ttl, "fragment": rec.fragment}})
        payload = rec.payload
        if rec.proto == 17 and rec.sport is not None:
            tree.append({"name": "UDP", "fields": {"src_port": rec.sport, "dst_port": rec.dport, "payload_len": len(payload)}})
            if 4500 in (rec.sport, rec.dport):
                if payload[:4] == b"\x00\x00\x00\x00":
                    tree.append({"name": "NAT-T", "fields": {"non-ESP marker": "00 00 00 00 (IKE inside UDP 4500)"}})
                    payload = payload[4:]
                    self._ike_tree(tree, payload)
                elif len(payload) == 1:
                    tree.append({"name": "NAT-T keepalive", "fields": {"byte": payload.hex()}})
                else:
                    self._esp_tree(tree, payload, udp=True)
            elif 500 in (rec.sport, rec.dport):
                self._ike_tree(tree, payload)
        elif rec.proto == 6 and rec.sport is not None:
            tree.append({"name": "TCP", "fields": {"src_port": rec.sport, "dst_port": rec.dport, "payload_len": len(payload)}})
        elif rec.proto == 50:
            self._esp_tree(tree, payload, udp=False)
        elif rec.proto == 51:
            ah = parse_ah(payload)
            if ah:
                tree.append({"name": "Authentication Header", "fields": {"next_header": PROTO_NAMES.get(ah.next_header, ah.next_header), "spi": f"0x{ah.spi:08x}",
                                                                         "sequence": ah.seq, "icv_len": ah.icv_len, "header_len": ah.total_len,
                                                                         "note": "payload is authenticated but NOT encrypted"}})
        elif rec.proto in (1, 58):
            tree.append({"name": "ICMP" if rec.proto == 1 else "ICMPv6", "fields": {"type": payload[0] if payload else None, "code": payload[1] if len(payload) > 1 else None}})
        return {"n": n, "tree": tree, "hex": _hexdump(raw)}

    def _esp_tree(self, tree: list, payload: bytes, udp: bool) -> None:
        esp = parse_esp(payload)
        if not esp:
            tree.append({"name": "ESP", "fields": {"error": "too short"}})
            return
        tree.append({"name": "Encapsulating Security Payload" + (" (UDP-encapsulated)" if udp else ""),
                     "fields": {"spi": f"0x{esp.spi:08x}", "sequence": esp.seq, "esp_len": esp.total_len, "encrypted_payload+icv": esp.total_len - 8,
                                "mod_16": esp.total_len % 16, "mod_8": esp.total_len % 8, "mod_4": esp.total_len % 4,
                                "note": "ciphertext: only SPI, sequence number and length are visible; the framing is inferred from length residues"}})

    def _ike_tree(self, tree: list, payload: bytes) -> None:
        msg = parse_ike(payload)
        if not msg:
            tree.append({"name": "IKE", "fields": {"error": "cannot parse"}})
            return
        hdr = {"version": f"IKEv{msg.version}", "exchange": f"{msg.exchange_name} ({msg.exchange})", "spi_i": msg.spi_i, "spi_r": msg.spi_r,
               "flags": f"0x{msg.flags:02x} " + ("response" if msg.response else "request") + (" initiator" if msg.initiator else ""),
               "message_id": msg.msg_id, "length": msg.length,
               "encrypted": bool(msg.encrypted or msg.sk_len) and ("yes - payloads inside SK are ciphertext" if msg.version == 2 else "yes")
               or "no - all payloads readable"}
        if msg.truncated:
            hdr["truncated"] = "packet shorter than IKE length (snaplen)"
        if msg.errors:
            hdr["errors"] = "; ".join(msg.errors)
        tree.append({"name": "Internet Key Exchange", "fields": hdr})
        for p in msg.payloads:
            fields: dict = {"length": p.length}
            fields.update({k: v for k, v in (p.info or {}).items() if not isinstance(v, (bytes, bytearray))})
            tree.append({"name": f"Payload: {p.name} ({p.ptype})", "fields": fields})
        for pr in msg.proposals:
            tree.append({"name": f"Proposal {pr.protocol_name}#{pr.number}", "fields": {"summary": pr.summary(), "transforms": len(pr.transforms) or len(pr.v1_transforms)}})
        if msg.ke_group is not None:
            tree.append({"name": "Key Exchange", "fields": {"group": R.dh_name(msg.ke_group), "public_value_len": msg.ke_len,
                                                            "additional_ke": ", ".join(f"{R.dh_name(g)} ({n} B)" for g, n in msg.add_ke) or "-"}})
        for nt in msg.notifies:
            tree.append({"name": f"Notify: {nt['name']}", "fields": {k: v for k, v in nt.items() if k != "name"}})
        for v in msg.vendor_ids:
            from ..protocols.ike import vendor_label
            tree.append({"name": "Vendor ID", "fields": {"hex": v, "vendor": vendor_label(v)}})
        for i in msg.ids:
            tree.append({"name": "Identification (cleartext!)", "fields": i})

    def save_pcap(self, path: str) -> int:
        with self.lock:
            frames = list(self.frames)
        if not frames:
            return 0
        lt = Counter(f[2] for f in frames).most_common(1)[0][0]
        w = PcapWriter(path, linktype=lt)
        for _, ts, flt, raw in frames:
            if flt == lt:
                w.write(ts, raw)
        w.close()
        return w.count


# ------------------------------------------------------------------------- source factory
def make_source(kind: str, sink, **opts) -> BaseSource:
    if kind == "interface":
        return InterfaceSource(sink, opts["iface"])
    if kind == "replay":
        return ReplaySource(sink, opts["path"], speed=opts.get("speed", 1.0), loop=opts.get("loop", False), label=opts.get("label"))
    if kind == "agent":
        return AgentSource(sink, opts.get("agent", "agent"), opts.get("iface", "?"))
    raise ValueError(f"unknown source kind {kind}")
