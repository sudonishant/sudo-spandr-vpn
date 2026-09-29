"""Live mode: replay source -> incremental analyzer -> snapshot/alerts; REST + WebSocket API; agent ingest; pcap round-trip."""
import json
import os
import struct
import time

import pytest
from fastapi.testclient import TestClient

from ipsec_xray.api.app import app
from ipsec_xray.live.engine import LiveAnalyzer, make_source
from ipsec_xray.pcap.reader import PcapWriter, read_packets

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLE = os.path.join(ROOT, "samples", "hub_three_spokes_mixed_traffic.pcap")
LEGACY = os.path.join(ROOT, "samples", "legacy_ikev1_aggressive_3des.pcap")


def _run_replay(path, speed=60, interval=0.5, timeout=120):
    a = LiveAnalyzer(snapshot_interval=interval)
    events = []
    a.add_listener(lambda e: events.append(e))
    a.start(make_source("replay", a.on_frame, path=path, speed=speed, label="t"))
    t = time.time()
    while a.running and time.time() - t < timeout:
        time.sleep(0.2)
    return a, events


def test_replay_builds_live_session():
    a, events = _run_replay(SAMPLE)
    assert a.index > 6000 and a.counts["ike"] >= 12 and a.counts["esp"] > 6000
    kinds = {e["type"] for e in events}
    assert {"packets", "stats", "snapshot", "alert", "status"} <= kinds
    snap = a.snapshot
    assert len(snap["tunnels"]) == 3 and len(snap["ike"]) == 3
    assert snap["assessment"]["grade"] in ("B", "C") and 60 <= snap["assessment"]["score"] < 95
    # per-tunnel alerts + per-SA alerts + finding alerts
    ids = [x["id"] for x in a.alerts]
    assert ids.count("TUNNEL") == 3 and ids.count("IKE") == 3
    assert any(x["severity"] in ("medium", "high", "critical") for x in a.alerts)
    # rows look like a packet list
    row = next(r for r in a.rows if r["c"] == "ike")
    assert row["proto"] == "IKEv2" and "IKE_SA_INIT" in row["info"]
    esp = next(r for r in a.rows if r["c"] == "esp")
    assert esp["info"].startswith("SPI 0x")
    # packet detail decodes IKE payloads + ESP header + hexdump
    d = a.packet_detail(row["n"])
    names = [n["name"] for n in d["tree"]]
    assert "Internet Key Exchange" in names and any(n.startswith("Payload: SA") for n in names) and d["hex"]
    d2 = a.packet_detail(esp["n"])
    assert any("Encapsulating Security Payload" in n["name"] for n in d2["tree"])
    assert a.packet_detail(10 ** 9) is None


def test_legacy_replay_raises_critical_alerts_and_saves_pcap(tmp_path):
    a, _ = _run_replay(LEGACY, speed=80)
    sev = {x["severity"] for x in a.alerts}
    assert "critical" in sev or "high" in sev
    assert a.snapshot["assessment"]["grade"] in ("D", "F")
    assert any(r["c"] == "warn" for r in a.rows)          # aggressive mode rows highlighted
    out = tmp_path / "saved.pcap"
    n = a.save_pcap(str(out))
    assert n == a.index and out.stat().st_size > 1000
    assert len(read_packets(str(out))) == n


def test_pcap_writer_roundtrip(tmp_path):
    p = tmp_path / "w.pcap"
    w = PcapWriter(str(p))
    frames = read_packets(LEGACY)[:20]
    from scapy.utils import PcapReader
    with PcapReader(LEGACY) as rd:
        for i, pkt in enumerate(rd):
            if i >= 20:
                break
            w.write(float(pkt.time), bytes(pkt))
    w.close()
    again = read_packets(str(p))
    assert len(again) == len(frames) == 20
    assert [r.src for r in again] == [r.src for r in frames]


def test_live_api_and_websocket():
    c = TestClient(app)
    src = c.get("/api/live/sources").json()
    assert "interfaces" in src and any(s["name"] == "hub_three_spokes_mixed_traffic" for s in src["samples"])
    assert c.get("/api/live/status").json()["running"] is False
    with c.websocket_connect("/ws/live") as ws:
        hello = ws.receive_json()
        assert hello["type"] == "hello" and hello["status"]["running"] is False
        r = c.post("/api/live/start", json={"source": "sample", "sample": "hub_three_spokes_mixed_traffic", "speed": 60, "profile": "enterprise"})
        assert r.status_code == 200 and r.json()["running"] is True
        assert c.post("/api/live/start", json={"source": "sample", "sample": "hub_three_spokes_mixed_traffic"}).status_code == 409
        got = {"packets": 0, "snapshot": 0, "alert": 0, "stats": 0}
        rows = 0
        deadline = time.time() + 120
        done = False
        while time.time() < deadline and not done:
            msg = ws.receive_json()
            evs = msg["events"] if msg["type"] == "batch" else [msg]
            for e in evs:
                if e["type"] in got:
                    got[e["type"]] += 1
                if e["type"] == "packets":
                    rows += len(e["rows"])
                if e["type"] == "status" and not e["running"] and e["packets"] > 6000:
                    done = True
        assert done and got["packets"] > 0 and got["snapshot"] > 0 and got["alert"] > 0 and rows > 500
    st = c.get("/api/live/status").json()
    assert st["running"] is False and st["packets"] > 6000 and st["profile"] == "enterprise"
    snap = c.get("/api/live/snapshot").json()
    assert len(snap["tunnels"]) == 3 and snap["profile"] == "enterprise"
    pk = c.get("/api/live/packets?limit=50").json()
    assert len(pk["rows"]) == 50 and pk["total"] == st["packets"]
    n = pk["rows"][0]["n"]
    d = c.get(f"/api/live/packet/{n}").json()
    assert d["n"] == n and d["tree"]
    assert isinstance(c.get("/api/live/alerts").json(), list)
    # save -> full offline analysis of what was seen live
    r = c.post("/api/live/save?name=pytest_live&analyze=true&profile=enterprise").json()
    assert r["frames"] == st["packets"] and r["result_id"] and r["grade"]
    res = c.get(f"/api/results/{r['result_id']}").json()
    assert len(res["facts"]["tunnels"]) == 3
    # tidy up: the saved capture and its stored result
    assert c.delete(f"/api/results/{r['result_id']}").status_code == 200
    from ipsec_xray.api.live import CAPTURES
    try:
        os.remove(os.path.join(CAPTURES, r["file"]))
    except OSError:
        pass
    # profile switch re-assesses in place
    assert c.post("/api/live/profile?profile=government").json()["profile"] == "government"
    assert c.get("/api/live/snapshot").json()["profile"] == "government"
    c.post("/api/live/reset")
    assert c.get("/api/live/status").json()["packets"] == 0


def test_agent_websocket_ingest():
    c = TestClient(app)
    c.post("/api/live/reset")
    from scapy.utils import PcapReader
    frames = []
    with PcapReader(LEGACY) as rd:
        for i, pkt in enumerate(rd):
            frames.append(bytes(pkt))
            if i >= 400:
                break
    with c.websocket_connect("/ws/agent?name=pytest&iface=lo") as ws:
        buf = b""
        now = time.time()
        for i, raw in enumerate(frames):
            buf += struct.pack("!dII", now + i * 0.001, 1, len(raw)) + raw
            if len(buf) > 60000:
                ws.send_bytes(buf)
                buf = b""
        if buf:
            ws.send_bytes(buf)
        deadline = time.time() + 20
        while time.time() < deadline:
            st = c.get("/api/live/status").json()
            if st["packets"] >= len(frames):
                break
            time.sleep(0.2)
    st = c.get("/api/live/status").json()
    assert st["packets"] == len(frames) and st["source"]["kind"] == "agent" and st["source"]["agent"] == "pytest"
    snap = c.get("/api/live/snapshot").json()
    assert snap["ike"] and snap["ike"][0]["version"] == 1
    c.post("/api/live/stop")
    c.post("/api/live/reset")
