"""FastAPI application: REST API + static dashboard.

    uvicorn ipsec_xray.api.app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import time

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..assessment.engine import list_checks, list_profiles, list_threats
from ..ml.models import Models
from ..pipeline import analyze_file, reassess
from ..report.render import render_html, render_pdf
from .store import Store

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SAMPLES = os.environ.get("IPSEC_XRAY_SAMPLES", os.path.join(ROOT, "samples"))
WEBUI = os.path.join(os.path.dirname(__file__), "..", "webui")
MAX_UPLOAD = int(os.environ.get("IPSEC_XRAY_MAX_UPLOAD_MB", "200")) * 1024 * 1024

app = FastAPI(title="IPsec X-Ray API", version=__version__,
              description="AI-powered IPsec VPN protocol analyzer and security assessment framework (SIH26160).")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
store = Store()

# live capture / real-time analysis (REST + WebSockets) - registered before the SPA catch-all
from . import live as _live  # noqa: E402
_live.bind(store)
app.include_router(_live.router)


def _sample_manifest() -> dict:
    p = os.path.join(SAMPLES, "manifest.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}


@app.get("/api/health")
def health():
    m = Models.get()
    return {"status": "ok", "version": __version__, "models": m.available, "model_meta": m.meta.get("models", {}),
            "samples": len(_sample_manifest()), "results": len(store.list(10000)), "time": time.strftime("%Y-%m-%dT%H:%M:%S")}


@app.get("/api/profiles")
def profiles():
    return list_profiles()


def _check_profile(profile: str) -> str:
    if profile not in list_profiles():
        raise HTTPException(404, f"unknown profile '{profile}' - one of {', '.join(list_profiles())}")
    return profile


@app.get("/api/checks")
def checks(profile: str = "baseline"):
    return list_checks(_check_profile(profile))


@app.get("/api/threats")
def threats():
    return list_threats()


@app.get("/api/samples")
def samples():
    man = _sample_manifest()
    out = []
    for name, truth in man.items():
        path = os.path.join(SAMPLES, truth.get("file", name + ".pcap"))
        if os.path.exists(path):
            out.append({"name": name, **truth, "size_bytes": os.path.getsize(path)})
    return out


@app.get("/api/samples/{name}/download")
def sample_download(name: str):
    man = _sample_manifest()
    if name not in man:
        raise HTTPException(404, "unknown sample")
    path = os.path.join(SAMPLES, man[name].get("file", name + ".pcap"))
    return FileResponse(path, media_type="application/vnd.tcpdump.pcap", filename=os.path.basename(path))


@app.post("/api/samples/{name}/analyze")
async def sample_analyze(name: str, profile: str = Query("baseline")):
    _check_profile(profile)
    man = _sample_manifest()
    if name not in man:
        raise HTTPException(404, "unknown sample")
    path = os.path.join(SAMPLES, man[name].get("file", name + ".pcap"))
    result = await asyncio.to_thread(analyze_file, path, profile, os.path.basename(path))
    result["sample"] = name
    result["ground_truth"] = man[name]
    store.put(result)
    return result


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...), profile: str = Query("baseline")):
    _check_profile(profile)
    suffix = os.path.splitext(file.filename or "capture.pcap")[1].lower() or ".pcap"
    if suffix not in (".pcap", ".pcapng", ".cap", ".dmp"):
        raise HTTPException(400, "upload a .pcap / .pcapng file")
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        size = 0
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_UPLOAD:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(413, f"file larger than {MAX_UPLOAD // (1 << 20)} MB")
            tmp.write(chunk)
        path = tmp.name
    try:
        result = await asyncio.to_thread(analyze_file, path, profile, file.filename or "upload.pcap")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(422, f"could not analyze capture: {e}")
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    store.put(result)
    return result


@app.get("/api/results")
def results():
    return store.list()


@app.get("/api/results/{rid}")
def result(rid: str):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "no such result")
    return r


@app.post("/api/results/{rid}/reassess")
def result_reassess(rid: str, profile: str = Query("baseline")):
    _check_profile(profile)
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "no such result")
    r2 = reassess(r, profile)
    store.put(r2)
    return r2


@app.delete("/api/results/{rid}")
def result_delete(rid: str):
    if not store.delete(rid):
        raise HTTPException(404, "no such result")
    return {"deleted": rid}


@app.get("/api/results/{rid}/report.html")
def report_html(rid: str, kind: str = Query("technical")):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "no such result")
    return HTMLResponse(render_html(r, "executive" if kind == "executive" else "technical"))


@app.get("/api/results/{rid}/report.pdf")
def report_pdf(rid: str, kind: str = Query("technical")):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "no such result")
    pdf = render_pdf(r, "executive" if kind == "executive" else "technical")
    fn = f"ipsec-xray_{kind}_{r['name']}.pdf".replace(" ", "_")
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f'inline; filename="{fn}"'})


@app.get("/api/results/{rid}/report.json")
def report_json(rid: str):
    r = store.get(rid)
    if not r:
        raise HTTPException(404, "no such result")
    return JSONResponse(r, headers={"Content-Disposition": f'attachment; filename="ipsec-xray_{r["name"]}.json"'})


# --------------------------------------------------------------------------- dashboard (built React app)
if os.path.isdir(WEBUI) and os.path.exists(os.path.join(WEBUI, "index.html")):
    app.mount("/assets", StaticFiles(directory=os.path.join(WEBUI, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        candidate = os.path.join(WEBUI, full_path)
        if full_path and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(WEBUI, "index.html"))
else:
    @app.get("/", include_in_schema=False)
    def index():
        return HTMLResponse("<h2>IPsec X-Ray API is running.</h2><p>The dashboard has not been built yet: run "
                            "<code>cd frontend && npm install && npm run build</code>. API docs: <a href='/docs'>/docs</a></p>")
