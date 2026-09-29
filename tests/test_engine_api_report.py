"""Engine sanity, report rendering and REST API smoke tests."""
import io
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("IPSEC_XRAY_DATA", os.path.join(ROOT, "data", "test"))

from ipsec_xray.assessment import engine  # noqa: E402
from ipsec_xray.pipeline import analyze_file  # noqa: E402
from ipsec_xray.report import render  # noqa: E402

SAMPLE = os.path.join(ROOT, "samples", "enterprise_cbc_sha256_natt.pcap")
LEGACY = os.path.join(ROOT, "samples", "legacy_ikev1_aggressive_3des.pcap")


@pytest.fixture(scope="module")
def result():
    assert os.path.exists(SAMPLE), "run python -m ipsec_xray.testbed.generate first"
    return analyze_file(SAMPLE, profile="enterprise", name="enterprise")


# ---------------------------------------------------------------- engine
def test_catalogue_loads():
    checks = engine.list_checks("baseline")
    assert len(checks) == 66
    ids = [c["id"] for c in checks]
    assert len(ids) == len(set(ids)), "duplicate check ids"
    fams = {i.split("-")[0] for i in ids}
    assert fams == {"IKE", "AUTH", "ESP", "FS", "SEQ", "META", "NET", "ANOM"}
    assert len(engine.list_threats()) == 12
    assert set(engine.list_profiles()) == {"baseline", "enterprise", "government", "pqc_ready"}


def test_severity_differs_by_profile():
    base = {c["id"]: c["severity"] for c in engine.list_checks("baseline")}
    gov = {c["id"]: c["severity"] for c in engine.list_checks("government")}
    assert base != gov


def test_safe_evaluator_blocks_dangerous_code():
    scope = {"x": 1, "y": [1, 2]}
    assert engine.SafeEval(scope).eval("x == 1 and len(y) == 2") is True
    for bad in ("__import__('os')", "open('x')", "(lambda: 1)()", "y.append(3)", "[c for c in y]", "x := 2"):
        with pytest.raises(Exception):
            engine.SafeEval(scope).eval(bad)
    # attribute access only works on dict facts - object internals are unreachable
    for probe in ("().__class__", "x.__dict__", "y.__class__.__mro__"):
        assert engine.SafeEval(scope).eval(probe) is None
    assert engine.evaluate("nonsense(", scope, default="d") == "d"


def test_grade_bands():
    grades = engine.load_catalog()["scoring"]["grades"]
    grades = [(g["grade"], g["min"]) if isinstance(g, dict) else tuple(g) for g in grades]
    assert engine.grade_for(95, grades) == "A+" and engine.grade_for(94.9, grades) == "A"
    assert engine.grade_for(85, grades) == "A" and engine.grade_for(75, grades) == "B" and engine.grade_for(60, grades) == "C"
    assert engine.grade_for(40, grades) == "D" and engine.grade_for(39.9, grades) == "F"


def test_domain_caps_sum_to_100(result):
    doms = result["assessment"]["domains"]
    assert sum(d["cap"] for d in doms.values()) == 100
    for d in doms.values():
        assert 0 <= d["score"] <= d["cap"]


def test_score_consistency(result):
    a = result["assessment"]
    assert abs(sum(d["score"] for d in a["domains"].values()) - a["score"]) < 0.5  # per-domain rounding
    assert 0 <= a["risk_score"] <= 100
    assert 0 <= a["ai_confidence"] <= 100
    assert len(a["check_results"]) == a["checks_total"] == 66
    assert len(a["threats"]) == 12
    for t in a["threats"]:
        assert 1 <= t["likelihood"] <= 5 and 1 <= t["impact"] <= 5


def test_critical_caps_grade():
    res = analyze_file(os.path.join(ROOT, "samples", "terrible_ikev1_des_md5_null_esp.pcap"), profile="baseline")
    a = res["assessment"]
    assert a["counts"]["critical"] >= 1
    assert a["grade"] in ("D", "F")


# ---------------------------------------------------------------- reports
def test_html_reports(result):
    for kind in ("technical", "executive"):
        html = render.render_html(result, kind)
        assert "<html" in html.lower() and result["assessment"]["grade"] in html
        assert "IPsec X-Ray" in html
    assert len(render.render_html(result, "technical")) > len(render.render_html(result, "executive"))


def test_pdf_reports(result):
    for kind in ("technical", "executive"):
        pdf = render.render_pdf(result, kind)
        assert pdf[:5] == b"%PDF-" and len(pdf) > 5000


def test_gauge_and_narrative(result):
    svg = render.gauge_svg(result["assessment"]["score"], result["assessment"]["grade"])
    assert svg.startswith("<svg")
    text = render.narrative(result)
    assert isinstance(text, (str, list)) and len(text) > 0


# ---------------------------------------------------------------- API
@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient
    from ipsec_xray.api.app import app
    with TestClient(app) as c:
        yield c


def test_api_static_endpoints(client):
    assert client.get("/api/health").json()["status"] == "ok"
    assert len(client.get("/api/profiles").json()) == 4
    assert len(client.get("/api/checks?profile=government").json()) == 66
    assert len(client.get("/api/threats").json()) == 12
    assert client.get("/api/checks?profile=nope").status_code == 404
    assert client.get("/").status_code == 200


def test_api_sample_flow(client):
    samples = client.get("/api/samples").json()
    assert len(samples) >= 8
    r = client.post("/api/samples/legacy_ikev1_aggressive_3des/analyze?profile=baseline")
    assert r.status_code == 200
    body = r.json()
    rid = body["id"]
    assert body["ground_truth"]["ike_version"] == 1 and body["assessment"]["grade"] == "F"
    assert any(x["id"] == rid for x in client.get("/api/results").json())
    assert client.get(f"/api/results/{rid}").json()["assessment"]["score"] == body["assessment"]["score"]
    re = client.post(f"/api/results/{rid}/reassess?profile=government").json()
    assert re["profile"] == "government" and re["assessment"]["score"] <= body["assessment"]["score"]
    for fmt, ctype in (("html", "text/html"), ("pdf", "application/pdf"), ("json", "application/json")):
        resp = client.get(f"/api/results/{rid}/report.{fmt}?kind=executive")
        assert resp.status_code == 200 and ctype in resp.headers["content-type"], fmt
    assert client.delete(f"/api/results/{rid}").status_code == 200
    assert client.get(f"/api/results/{rid}").status_code == 404


def test_api_upload(client):
    with open(SAMPLE, "rb") as fh:
        data = fh.read()
    r = client.post("/api/analyze?profile=enterprise", files={"file": ("enterprise.pcap", io.BytesIO(data), "application/octet-stream")})
    assert r.status_code == 200
    body = r.json()
    assert body["name"] == "enterprise.pcap" and body["profile"] == "enterprise"
    assert body["assessment"]["grade"] in ("B", "C")
    client.delete(f"/api/results/{body['id']}")


def test_api_rejects_garbage(client):
    r = client.post("/api/analyze", files={"file": ("x.txt", io.BytesIO(b"hello"), "text/plain")})
    assert r.status_code in (400, 415, 422)
    r = client.post("/api/analyze", files={"file": ("x.pcap", io.BytesIO(b"not a pcap at all"), "application/octet-stream")})
    assert r.status_code in (400, 422)
