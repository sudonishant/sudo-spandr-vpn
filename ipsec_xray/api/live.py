"""Live capture API: REST controls + WebSocket stream for the browser + WebSocket ingest for capture agents."""
from __future__ import annotations

import asyncio
import json
import os
import struct
import tempfile
import time
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from ..assessment.engine import list_profiles
from ..live.engine import LiveAnalyzer, make_source
from ..live.sources import AgentSource, can_sniff, list_interfaces
from ..pipeline import analyze_file

router = APIRouter()
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.environ.get("IPSEC_XRAY_SAMPLES", os.path.join(ROOT, "samples"))
DATA = os.environ.get("IPSEC_XRAY_DATA", os.path.join(ROOT, "data"))
CAPTURES = os.path.join(DATA, "captures")

analyzer = LiveAnalyzer()
_clients: set["_Client"] = set()
_agents: dict[str, dict] = {}     # connected capture agents (name -> info), independent of the analyzer state
_loop: Optional[asyncio.AbstractEventLoop] = None
_store = None   # injected by app.py


def bind(store, loop: asyncio.AbstractEventLoop | None = None) -> None:
    global _store
    _store = store


class _Client:
    def __init__(self, ws: WebSocket):
        self.ws = ws
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=2000)

    def push(self, event: dict) -> None:
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:   # slow consumer: drop packet batches, never control events
            if event.get("type") != "packets":
                try:
                    self.queue.get_nowait()
                    self.queue.put_nowait(event)
                except Exception:
                    pass


def _fanout(event: dict) -> None:
    """Called from analyzer threads: hop onto the event loop and enqueue for every browser."""
    loop = _loop
    if loop is None or loop.is_closed():
        return
    for c in list(_clients):
        loop.call_soon_threadsafe(c.push, event)


analyzer.add_listener(_fanout)


# ---------------------------------------------------------------------------- REST
class StartRequest(BaseModel):
    source: str = "replay"            # interface | replay | sample | agent
    iface: Optional[str] = None
    sample: Optional[str] = None
    path: Optional[str] = None
    speed: float = 1.0
    loop: bool = False
    profile: str = "baseline"
    reset: bool = True


@router.get("/api/live/sources")
def live_sources():
    ok, why = can_sniff()
    man_path = os.path.join(SAMPLES, "manifest.json")
    samples = []
    if os.path.exists(man_path):
        with open(man_path) as f:
            man = json.load(f)
        samples = [{"name": k, "description": v.get("description", ""), "expected_grade": v.get("expected_grade", [])} for k, v in man.items()
                   if os.path.exists(os.path.join(SAMPLES, v.get("file", k + ".pcap")))]
    uploads = []
    if os.path.isdir(CAPTURES):
        for fn in sorted(os.listdir(CAPTURES))[-30:]:
            if fn.endswith((".pcap", ".pcapng")):
                p = os.path.join(CAPTURES, fn)
                uploads.append({"name": fn, "size": os.path.getsize(p)})
    return {"interfaces": list_interfaces(), "can_sniff": ok, "sniff_note": why, "samples": samples, "captures": uploads,
            "profiles": list_profiles(), "agents": [{"name": k, **v} for k, v in _agents.items()]}


@router.post("/api/live/start")
def live_start(req: StartRequest):
    if req.profile not in list_profiles():
        raise HTTPException(404, "unknown profile")
    if analyzer.running:
        raise HTTPException(409, "capture already running - stop it first")
    if req.reset:
        analyzer.reset()
    analyzer.profile = req.profile
    if req.source == "interface":
        if not req.iface:
            raise HTTPException(400, "iface required")
        ok, why = can_sniff()
        if not ok:
            raise HTTPException(403, f"cannot capture from this process: {why}")
        src = make_source("interface", analyzer.on_frame, iface=req.iface)
    elif req.source in ("replay", "sample"):
        if req.sample:
            man_path = os.path.join(SAMPLES, "manifest.json")
            with open(man_path) as f:
                man = json.load(f)
            if req.sample not in man:
                raise HTTPException(404, "unknown sample")
            path = os.path.join(SAMPLES, man[req.sample].get("file", req.sample + ".pcap"))
            label = req.sample
        elif req.path:
            path = os.path.join(CAPTURES, os.path.basename(req.path))
            if not os.path.exists(path):
                raise HTTPException(404, "no such capture file")
            label = os.path.basename(path)
        else:
            raise HTTPException(400, "sample or path required")
        src = make_source("replay", analyzer.on_frame, path=path, speed=req.speed, loop=req.loop, label=label)
    elif req.source == "agent":
        first = next(iter(_agents.items()), None)
        src = make_source("agent", analyzer.on_frame, agent=first[0] if first else "waiting for agent...",
                          iface=req.iface or (first[1]["iface"] if first else "?"))
    else:
        raise HTTPException(400, "source must be interface | replay | sample | agent")
    analyzer.start(src)
    return analyzer.status()


@router.post("/api/live/stop")
def live_stop():
    analyzer.stop()
    return analyzer.status()


@router.post("/api/live/reset")
def live_reset():
    analyzer.reset()
    return analyzer.status()


@router.get("/api/live/status")
def live_status():
    return {**analyzer.status(), "stats": analyzer.stats(), "agents": [{"name": k, **v} for k, v in _agents.items()]}


@router.post("/api/live/profile")
def live_profile(profile: str = Query("baseline")):
    if profile not in list_profiles():
        raise HTTPException(404, "unknown profile")
    analyzer.set_profile(profile)
    return analyzer.status()


@router.get("/api/live/snapshot")
def live_snapshot():
    if analyzer.snapshot is None:
        analyzer._refresh_snapshot(force=True)
    return analyzer.snapshot or {}


@router.get("/api/live/packets")
def live_packets(limit: int = Query(500, le=4000)):
    rows = list(analyzer.rows)
    return {"rows": rows[-limit:], "total": analyzer.index}


@router.get("/api/live/packet/{n}")
def live_packet(n: int):
    d = analyzer.packet_detail(n)
    if d is None:
        raise HTTPException(404, "packet no longer in the buffer")
    return d


@router.get("/api/live/alerts")
def live_alerts():
    return list(analyzer.alerts)


@router.post("/api/live/save")
def live_save(name: Optional[str] = Query(None), analyze: bool = Query(True), profile: str = Query("baseline")):
    """Write the captured frames to a pcap under data/captures and (optionally) run the full offline analysis."""
    os.makedirs(CAPTURES, exist_ok=True)
    fn = (name or f"live_{time.strftime('%Y%m%d_%H%M%S')}").replace("/", "_")
    if not fn.endswith(".pcap"):
        fn += ".pcap"
    path = os.path.join(CAPTURES, fn)
    n = analyzer.save_pcap(path)
    if n == 0:
        raise HTTPException(400, "nothing captured yet")
    out = {"file": fn, "frames": n, "size": os.path.getsize(path)}
    if analyze and _store is not None:
        res = analyze_file(path, profile=profile, name=fn)
        _store.put(res)
        out["result_id"] = res["id"]
        out["grade"] = res["assessment"]["grade"]
        out["score"] = res["assessment"]["score"]
    return out


@router.post("/api/live/upload")
async def live_upload(file: UploadFile = File(...)):
    """Upload a pcap to replay through the live view (stored under data/captures)."""
    suffix = os.path.splitext(file.filename or "x.pcap")[1].lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(400, "upload a .pcap / .pcapng file")
    os.makedirs(CAPTURES, exist_ok=True)
    safe = os.path.basename(file.filename or "upload.pcap").replace(" ", "_")
    path = os.path.join(CAPTURES, safe)
    with open(path, "wb") as out:
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)
    return {"name": safe, "size": os.path.getsize(path)}


# ---------------------------------------------------------------------------- WebSockets
@router.websocket("/ws/live")
async def ws_live(ws: WebSocket):
    global _loop
    await ws.accept()
    _loop = asyncio.get_running_loop()
    client = _Client(ws)
    _clients.add(client)
    try:
        await ws.send_text(json.dumps(analyzer.hello(), default=str))
        while True:
            # coalesce: send whatever is queued; fall back to a heartbeat
            try:
                ev = await asyncio.wait_for(client.queue.get(), timeout=15)
            except asyncio.TimeoutError:
                await ws.send_text(json.dumps({"type": "ping", "t": time.time()}))
                continue
            batch = [ev]
            while not client.queue.empty() and len(batch) < 50:
                batch.append(client.queue.get_nowait())
            # merge consecutive packet batches
            merged: list[dict] = []
            for e in batch:
                if e.get("type") == "packets" and merged and merged[-1].get("type") == "packets":
                    merged[-1]["rows"] = (merged[-1]["rows"] + e["rows"])[-600:]
                    merged[-1]["dropped"] = merged[-1].get("dropped", 0) + e.get("dropped", 0)
                else:
                    merged.append(dict(e))
            await ws.send_text(json.dumps({"type": "batch", "events": merged}, default=str))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _clients.discard(client)


@router.websocket("/ws/agent")
async def ws_agent(ws: WebSocket, name: str = Query("agent"), iface: str = Query("?"), profile: str = Query("baseline")):
    """Capture agents stream binary frames: struct '!dI' (timestamp, linktype) + raw frame bytes."""
    global _loop
    await ws.accept()
    _loop = asyncio.get_running_loop()
    if not analyzer.running:
        analyzer.reset()
        analyzer.profile = profile if profile in list_profiles() else "baseline"
        analyzer.start(make_source("agent", analyzer.on_frame, agent=name, iface=iface))
    src = analyzer.source
    if isinstance(src, AgentSource):
        src.agent_name, src.iface = name, iface
        _fanout({"type": "status", **analyzer.status()})
    _agents[name] = {"iface": iface, "since": time.time(), "frames": 0}
    n = 0
    try:
        while True:
            msg = await ws.receive()
            if msg.get("type") == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None:
                txt = msg.get("text") or ""
                if txt == "ping":
                    await ws.send_text("pong")
                continue
            off = 0
            while off + 16 <= len(data):
                ts, lt, ln = struct.unpack_from("!dII", data, off)
                off += 16
                raw = data[off:off + ln]
                off += ln
                if isinstance(analyzer.source, AgentSource) and analyzer.running:
                    analyzer.source.push(ts, lt, raw)
                n += 1
            _agents[name]["frames"] = n
            if n % 500 == 0:
                await ws.send_text(json.dumps({"ack": n}))
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        _agents.pop(name, None)
        if isinstance(analyzer.source, AgentSource):
            analyzer._alert("info", "AGENT", f"agent {name} disconnected after {n} frames", "", "")
