"""Reconstruct IKE SAs, ESP/AH flows and cleartext side-traffic from a list of packet records."""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from ..pcap.reader import PacketRecord
from ..protocols import registry as R
from ..protocols.esp import parse_ah, parse_esp
from ..protocols.ike import IKEMessage, parse_ike, vendor_label


@dataclass
class IKEExchange:
    ts: float
    exchange: str
    direction: str          # "i->r" or "r->i"
    length: int
    msg_id: int
    response: bool
    encrypted_len: int
    payloads: list[str]
    notifies: list[str]
    src: str
    dst: str
    ke_group: Optional[int] = None
    ke_len: Optional[int] = None


@dataclass
class IKESA:
    version: int
    spi_i: str
    spi_r: str
    initiator: str
    responder: str
    ports: set = field(default_factory=set)
    ipver: int = 4
    exchanges: list[IKEExchange] = field(default_factory=list)
    offered: list = field(default_factory=list)        # proposals offered by the initiator (IKE)
    chosen: Optional[object] = None                    # proposal selected by the responder (IKE)
    ke_group: Optional[int] = None
    ke_len: Optional[int] = None
    add_ke: list = field(default_factory=list)
    nonce_lens: list = field(default_factory=list)
    notifies: set = field(default_factory=set)
    vendor_ids: list = field(default_factory=list)
    ids: list = field(default_factory=list)
    v1_mode: Optional[str] = None
    v1_attrs: dict = field(default_factory=dict)
    child_rekeys: list = field(default_factory=list)   # dicts: ts, req_len, resp_len
    ike_rekeys: int = 0
    sig_hash_algs: set = field(default_factory=set)
    informational: int = 0
    deletes: int = 0
    errors: list = field(default_factory=list)
    ike_auth_lens: list = field(default_factory=list)
    intermediate: int = 0
    cert_seen: bool = False
    certreq_seen: bool = False
    hash_or_sig_plain: bool = False
    first_ts: float = 0.0
    last_ts: float = 0.0
    parse_errors: int = 0

    @property
    def nat_t(self) -> bool:
        return 4500 in self.ports

    @property
    def natt_capable(self) -> bool:
        return any(n.startswith("NAT_DETECTION") for n in self.notifies) or any(v[1].lower().find("nat-t") >= 0 for v in self.vendor_ids)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)


@dataclass
class ESPFlow:
    src: str
    dst: str
    spi: int
    ipver: int
    udp_encap: bool
    protocol: str = "ESP"           # or "AH"
    pkts: list = field(default_factory=list)      # (ts, total_len, seq)
    icv_len: Optional[int] = None   # AH only
    ah_next_header: Optional[int] = None
    ah_inner: Counter = field(default_factory=Counter)   # AH only: (inner proto, low port / icmp type) - cleartext
    null_inner: Counter = field(default_factory=Counter)  # ESP with NULL encryption: inner (proto, low port) read in cleartext
    null_mode: Counter = field(default_factory=Counter)   # tunnel/transport votes from the decoded NULL-ESP trailer
    null_icv: Counter = field(default_factory=Counter)    # ICV length consistent with the trailer
    null_misses: int = 0
    samples: list = field(default_factory=list)   # (first payload byte, byte entropy) for up to 64 packets

    def note_ah_inner(self, inner: bytes, next_header: int) -> None:
        """AH leaves the payload in cleartext: record the inner protocol and ports (tunnel or transport mode)."""
        try:
            proto, off = next_header, 0
            if next_header == 4 and len(inner) >= 20:          # IP-in-IP (tunnel mode)
                proto, off = inner[9], (inner[0] & 0x0F) * 4
            elif next_header == 41 and len(inner) >= 40:       # IPv6-in-IP (tunnel mode)
                proto, off = inner[6], 40
            body = inner[off:]
            if proto in (6, 17) and len(body) >= 4:
                sport, dport = int.from_bytes(body[0:2], "big"), int.from_bytes(body[2:4], "big")
                self.ah_inner[(proto, min(sport, dport))] += 1
            elif proto in (1, 58) and len(body) >= 1:
                self.ah_inner[(proto, body[0])] += 1
            else:
                self.ah_inner[(proto, -1)] += 1
        except Exception:
            pass

    def note_payload(self, data: bytes) -> None:
        """Keep entropy evidence: encrypted payloads look random, NULL-encrypted ones show the inner packet."""
        if len(self.null_inner) + self.null_misses < 256:
            self._probe_null_esp(data)
        if len(self.samples) >= 64 or len(data) < 48:
            return
        body = data[8:-12] if len(data) > 60 else data[8:]
        cnt = Counter(body)
        n = len(body)
        ent = -sum((c / n) * math.log2(c / n) for c in cnt.values())
        norm = ent / math.log2(min(n, 256))          # 1.0 = indistinguishable from random for this length
        self.samples.append((data[8], round(norm, 3)))

    def _probe_null_esp(self, data: bytes) -> None:
        """ESP with ENCR_NULL has no IV: the inner packet starts right after SPI+seq and the trailer
        (pad 1,2,3,... | pad-length | next-header) sits in front of the ICV. When both structures are
        consistent we record the inner protocol/ports (cleartext) - the same evidence AH gives for free."""
        body = data[8:]
        if len(body) < 24:
            return
        for icv in (12, 16, 24, 32):
            if len(body) < icv + 2:
                continue
            nh, padlen = body[-icv - 1], body[-icv - 2]
            if padlen > 255 or len(body) < icv + 2 + padlen:
                continue
            pad = body[-icv - 2 - padlen:-icv - 2] if padlen else b""
            if pad != bytes(range(1, padlen + 1)):
                continue
            inner = body[:len(body) - icv - 2 - padlen]
            if nh == 4 and len(inner) >= 20 and inner[0] >> 4 == 4 and int.from_bytes(inner[2:4], "big") == len(inner):
                proto, off, mode = inner[9], (inner[0] & 0x0F) * 4, "tunnel"
            elif nh == 41 and len(inner) >= 40 and inner[0] >> 4 == 6 and int.from_bytes(inner[4:6], "big") + 40 == len(inner):
                proto, off, mode = inner[6], 40, "tunnel"
            elif nh in (6, 17, 1, 58):
                proto, off, mode = nh, 0, "transport"
            else:
                continue
            seg = inner[off:]
            if proto in (6, 17) and len(seg) >= 4:
                key = (proto, min(int.from_bytes(seg[0:2], "big"), int.from_bytes(seg[2:4], "big")))
            elif proto in (1, 58) and len(seg) >= 1:
                key = (proto, seg[0])
            else:
                key = (proto, -1)
            self.null_inner[key] += 1
            self.null_mode[mode] += 1
            self.null_icv[icv] += 1
            return
        self.null_misses += 1

    def entropy_summary(self) -> dict:
        if not self.samples:
            return {"n": 0, "mean_entropy": None, "ip_header_like": 0.0}
        ents = [e for _, e in self.samples]
        hdr = sum(1 for b, _ in self.samples if b in (0x45, 0x60)) / len(self.samples)
        return {"n": len(self.samples), "mean_entropy": round(sum(ents) / len(ents), 3), "ip_header_like": round(hdr, 3)}

    # ---- derived
    @property
    def count(self) -> int:
        return len(self.pkts)

    @property
    def bytes(self) -> int:
        return sum(p[1] for p in self.pkts)

    @property
    def first_ts(self) -> float:
        return self.pkts[0][0] if self.pkts else 0.0

    @property
    def last_ts(self) -> float:
        return self.pkts[-1][0] if self.pkts else 0.0

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    def lengths(self) -> list[int]:
        return [p[1] for p in self.pkts]

    def seq_stats(self) -> dict:
        seqs = [p[2] for p in self.pkts]
        if not seqs:
            return {"monotonic": True, "duplicates": 0, "gaps": 0, "max": 0, "min": 0, "reorders": 0, "starts_at_one": False}
        dup = 0
        reorders = 0
        gaps = 0
        seen = set()
        prev = None
        for s in seqs:
            if s in seen:
                dup += 1
            seen.add(s)
            if prev is not None:
                if s < prev:
                    reorders += 1
                elif s > prev + 1:
                    gaps += s - prev - 1
            prev = s
        return {"monotonic": reorders == 0 and dup == 0, "duplicates": dup, "gaps": gaps, "max": max(seqs), "min": min(seqs),
                "reorders": reorders, "starts_at_one": min(seqs) == 1}


@dataclass
class Session:
    packets_total: int = 0
    ike_sas: dict = field(default_factory=dict)         # spi_i -> IKESA
    esp_flows: dict = field(default_factory=dict)       # (src,dst,spi) -> ESPFlow
    ah_flows: dict = field(default_factory=dict)
    ike_messages: int = 0
    cleartext: dict = field(default_factory=lambda: defaultdict(int))   # (proto/port label) -> count between IPsec peers
    endpoints: set = field(default_factory=set)
    ipvers: set = field(default_factory=set)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    fragments: int = 0
    non_ipsec_packets: int = 0
    tcp_4500_packets: int = 0
    notes: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


def _direction(sa: IKESA, src: str) -> str:
    return "i->r" if src == sa.initiator else "r->i"


def _handle_ike(sess: Session, rec: PacketRecord, msg: IKEMessage) -> None:
    sess.ike_messages += 1
    key = msg.spi_i
    sa = sess.ike_sas.get(key)
    if sa is None:
        # first message we see: for IKEv2 use the initiator flag, for IKEv1 the first sender is the initiator
        init_is_src = msg.initiator if msg.version == 2 else True
        sa = IKESA(msg.version, msg.spi_i, msg.spi_r, rec.src if init_is_src else rec.dst, rec.dst if init_is_src else rec.src,
                   ipver=rec.ipver, first_ts=rec.ts)
        sess.ike_sas[key] = sa
    if sa.spi_r == "0" * 16 and msg.spi_r != "0" * 16:
        sa.spi_r = msg.spi_r
    sa.ports.update({rec.sport, rec.dport} - {None})
    sa.last_ts = rec.ts
    direction = _direction(sa, rec.src)
    ex = IKEExchange(rec.ts, msg.exchange_name, direction, msg.length, msg.msg_id, msg.response, msg.sk_len,
                     msg.payload_names, msg.notify_names(), rec.src, rec.dst, msg.ke_group, msg.ke_len)
    sa.exchanges.append(ex)
    sa.parse_errors += len(msg.errors)
    for n in msg.notifies:
        sa.notifies.add(n["name"])
        if n["type"] == 16431 and n.get("data"):
            raw = bytes.fromhex(n["data"])
            sa.sig_hash_algs.update(int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw) - 1, 2))
        if n["name"] in ("NO_PROPOSAL_CHOSEN", "AUTHENTICATION_FAILED", "INVALID_KE_PAYLOAD", "INVALID_SYNTAX", "TS_UNACCEPTABLE"):
            sa.errors.append(n["name"])
    for v in msg.vendor_ids:
        lab = vendor_label(v)
        if (v, lab) not in sa.vendor_ids:
            sa.vendor_ids.append((v, lab))
    for i in msg.ids:
        sa.ids.append(dict(i, direction=direction, exchange=msg.exchange_name))
    if msg.cert_len:
        sa.cert_seen = True
    if msg.certreq:
        sa.certreq_seen = True
    if msg.hash_or_sig_plain:
        sa.hash_or_sig_plain = True
    if msg.nonce_len:
        sa.nonce_lens.append(msg.nonce_len)

    if msg.version == 2:
        if msg.exchange == 34:  # IKE_SA_INIT
            if not msg.response and msg.proposals and not sa.offered:
                sa.offered = msg.proposals
            if msg.response and msg.proposals:
                sa.chosen = msg.proposals[0]
            if msg.ke_group is not None:
                if msg.response or sa.ke_group is None:
                    sa.ke_group, sa.ke_len = msg.ke_group, msg.ke_len
            if msg.add_ke:
                sa.add_ke = msg.add_ke
        elif msg.exchange == 35:
            sa.ike_auth_lens.append(msg.length)
        elif msg.exchange == 36:  # CREATE_CHILD_SA (encrypted: only the size is visible)
            if not msg.response:
                sa.child_rekeys.append({"ts": rec.ts, "req_len": msg.length, "resp_len": None, "sk_len": msg.sk_len, "msg_id": msg.msg_id})
            else:
                for r in reversed(sa.child_rekeys):
                    if r["msg_id"] == msg.msg_id and r["resp_len"] is None:
                        r["resp_len"] = msg.length
                        break
        elif msg.exchange == 37:
            sa.informational += 1
            if "D" in msg.payload_names:
                sa.deletes += 1
        elif msg.exchange == 43:
            sa.intermediate += 1
    else:
        if msg.exchange == 2:
            sa.v1_mode = sa.v1_mode or "main"
        elif msg.exchange == 4:
            sa.v1_mode = "aggressive"
        elif msg.exchange == 32:   # Quick Mode: encrypted, size reveals KE payload (PFS)
            if not msg.encrypted:
                pass
            sa.child_rekeys.append({"ts": rec.ts, "req_len": msg.length, "resp_len": None, "sk_len": msg.sk_len,
                                    "msg_id": msg.msg_id, "quick_mode": True})
        elif msg.exchange == 5:
            sa.informational += 1
        if msg.proposals:
            if direction == "i->r" and not sa.offered:
                sa.offered = msg.proposals
            elif direction == "r->i":
                sa.chosen = msg.proposals[0]
            if sa.chosen is None and sa.offered and msg.exchange == 4 and direction == "r->i":
                sa.chosen = msg.proposals[0]
        if msg.ke_len and direction == "i->r":
            sa.ke_len = msg.ke_len
        for p in (msg.proposals or []):
            if p.v1_attrs:
                # responder's answer is authoritative; before that, the initiator's first (preferred) transform
                if direction == "r->i" or not sa.v1_attrs:
                    sa.v1_attrs = dict(p.v1_attrs)
                if "GROUP" in p.v1_attrs and (direction == "r->i" or sa.ke_group is None):
                    sa.ke_group = p.v1_attrs["GROUP"]


MAX_FLOW_PACKETS = 60000      # live mode: keep the newest N packets per flow (memory bound)


class SessionBuilder:
    """Incremental session construction: feed() packets one by one, finish() any time for a snapshot.

    build_session() below is the one-shot wrapper used for files; the live analyzer keeps a builder around
    and calls finish() periodically (finish is idempotent - it recomputes the derived counters)."""

    def __init__(self):
        self.sess = Session()
        self.ipsec_hosts: set = set()
        self.pending: list[PacketRecord] = []

    def feed(self, rec: PacketRecord) -> str:
        """Returns a coarse classification of the packet: 'ike', 'esp', 'ah', 'keepalive' or 'other'."""
        kind = "other"
        self.sess.packets_total += 1
        self.sess.first_ts = rec.ts if self.sess.first_ts is None else min(self.sess.first_ts, rec.ts)
        self.sess.last_ts = rec.ts if self.sess.last_ts is None else max(self.sess.last_ts, rec.ts)
        self.sess.ipvers.add(rec.ipver)
        if rec.fragment:
            self.sess.fragments += 1
        handled = False
        if rec.proto == 17 and rec.sport is not None and (rec.sport in R.IKE_PORTS or rec.dport in R.IKE_PORTS):
            payload = rec.payload
            udp_encap = 4500 in (rec.sport, rec.dport)
            if udp_encap and len(payload) >= 4 and payload[:4] == b"\x00\x00\x00\x00":
                msg = parse_ike(payload[4:])
                if msg:
                    _handle_ike(self.sess, rec, msg)
                    handled = True
                    kind = "ike"
            elif udp_encap and len(payload) >= 8:
                if len(payload) == 1 and payload == b"\xff":
                    handled = True      # NAT keepalive
                    kind = "keepalive"
                else:
                    esp = parse_esp(payload)
                    if esp:
                        key = (rec.src, rec.dst, esp.spi)
                        fl = self.sess.esp_flows.get(key)
                        if fl is None:
                            fl = self.sess.esp_flows[key] = ESPFlow(rec.src, rec.dst, esp.spi, rec.ipver, True)
                        fl.pkts.append((rec.ts, max(esp.total_len, rec.l4_len), esp.seq))
                        fl.note_payload(payload)
                        handled = True
                        kind = "esp"
            elif udp_encap and len(payload) == 1:
                handled = True
                kind = "keepalive"
            else:
                msg = parse_ike(payload)
                if msg:
                    _handle_ike(self.sess, rec, msg)
                    handled = True
                    kind = "ike"
            if handled:
                self.ipsec_hosts.update({rec.src, rec.dst})
        elif rec.proto == 50:
            esp = parse_esp(rec.payload)
            if esp:
                key = (rec.src, rec.dst, esp.spi)
                fl = self.sess.esp_flows.get(key)
                if fl is None:
                    fl = self.sess.esp_flows[key] = ESPFlow(rec.src, rec.dst, esp.spi, rec.ipver, False)
                fl.pkts.append((rec.ts, max(esp.total_len, rec.l4_len), esp.seq))
                fl.note_payload(rec.payload)
                handled = True
                kind = "esp"
                self.ipsec_hosts.update({rec.src, rec.dst})
        elif rec.proto == 51:
            ah = parse_ah(rec.payload)
            if ah:
                key = (rec.src, rec.dst, ah.spi)
                fl = self.sess.ah_flows.get(key)
                if fl is None:
                    fl = self.sess.ah_flows[key] = ESPFlow(rec.src, rec.dst, ah.spi, rec.ipver, False, protocol="AH",
                                                       icv_len=ah.icv_len, ah_next_header=ah.next_header)
                fl.pkts.append((rec.ts, rec.ip_len, ah.seq))
                if len(fl.pkts) <= 256:
                    fl.note_ah_inner(rec.payload[ah.total_len:], ah.next_header)
                handled = True
                kind = "ah"
                self.ipsec_hosts.update({rec.src, rec.dst})
        if not handled:
            if rec.proto == 6 and 4500 in (rec.sport, rec.dport):
                self.sess.tcp_4500_packets += 1
                if rec.payload.startswith(b"IKETCP"):
                    self.sess.notes.append("RFC 8229 TCP encapsulation stream prefix seen")
            self.pending.append(rec)
        return kind

    def finish(self) -> Session:
        sess = self.sess
        sess.cleartext = Counter()
        sess.non_ipsec_packets = 0
        for rec in self.pending:
            sess.non_ipsec_packets += 1
            if rec.src in self.ipsec_hosts and rec.dst in self.ipsec_hosts:
                if rec.proto == 17:
                    lab = f"UDP/{min(rec.sport or 0, rec.dport or 0)}"
                elif rec.proto == 6:
                    lab = f"TCP/{min(rec.sport or 0, rec.dport or 0)}"
                elif rec.proto in (1, 58):
                    lab = "ICMP"
                else:
                    lab = f"IP/{rec.proto}"
                sess.cleartext[lab] += 1
        sess.endpoints = set(self.ipsec_hosts)
        for fl in list(sess.esp_flows.values()) + list(sess.ah_flows.values()):
            if len(fl.pkts) > MAX_FLOW_PACKETS:
                del fl.pkts[:len(fl.pkts) - MAX_FLOW_PACKETS]
            fl.pkts.sort(key=lambda p: p[0])
        if len(self.pending) > MAX_FLOW_PACKETS:
            del self.pending[:len(self.pending) - MAX_FLOW_PACKETS]
        return sess


def build_session(records: list[PacketRecord]) -> Session:
    b = SessionBuilder()
    for rec in records:
        b.feed(rec)
    return b.finish()


def pair_flows(sess: Session) -> list[dict]:
    """Group ESP/AH flows into bidirectional tunnels between host pairs and detect re-keys (new SPI, same direction)."""
    groups: dict = defaultdict(list)
    for fl in list(sess.esp_flows.values()) + list(sess.ah_flows.values()):
        key = tuple(sorted((fl.src, fl.dst)))
        groups[key].append(fl)
    tunnels = []
    for (a, b), flows in groups.items():
        flows.sort(key=lambda f: f.first_ts)
        per_dir: dict = defaultdict(list)
        for f in flows:
            per_dir[(f.src, f.dst)].append(f)
        rekeys = []
        lifetimes = []
        for d, fls in per_dir.items():
            for prev, nxt in zip(fls, fls[1:]):
                rekeys.append({"direction": f"{d[0]}->{d[1]}", "old_spi": prev.spi, "new_spi": nxt.spi, "ts": nxt.first_ts,
                               "old_pkts": prev.count, "old_bytes": prev.bytes})
                lifetimes.append(nxt.first_ts - prev.first_ts)
        tunnels.append({"peers": (a, b), "flows": flows, "rekeys": rekeys, "lifetimes": lifetimes,
                        "protocol": flows[0].protocol, "udp_encap": any(f.udp_encap for f in flows),
                        "ipver": flows[0].ipver})
    return tunnels
