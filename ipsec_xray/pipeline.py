"""End-to-end orchestration: PCAP -> packets -> session -> facts -> assessment -> result document."""
from __future__ import annotations

import json
import os
import time
import uuid

from . import __version__
from .analysis.inference import build_facts
from .analysis.session import build_session
from .assessment.engine import assess
from .pcap.reader import read_packets


def analyze_file(path: str, profile: str = "baseline", name: str | None = None, limit: int | None = None) -> dict:
    t0 = time.time()
    records = read_packets(path, limit=limit)
    t1 = time.time()
    session = build_session(records)
    t2 = time.time()
    facts = build_facts(session, name or os.path.basename(path))
    t3 = time.time()
    assessment = assess(facts, profile)
    t4 = time.time()
    result = {
        "id": uuid.uuid4().hex[:12],
        "name": name or os.path.basename(path),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "version": __version__,
        "profile": assessment["profile"],
        "timing": {"read_s": round(t1 - t0, 3), "session_s": round(t2 - t1, 3), "inference_s": round(t3 - t2, 3),
                   "assessment_s": round(t4 - t3, 3), "total_s": round(t4 - t0, 3)},
        "facts": facts,
        "assessment": assessment,
    }
    # make sure everything is JSON-serialisable (sets, tuples, numpy scalars)
    return json.loads(json.dumps(result, default=_default))


def reassess(result: dict, profile: str) -> dict:
    result = dict(result)
    result["assessment"] = assess(result["facts"], profile)
    result["profile"] = result["assessment"]["profile"]
    return json.loads(json.dumps(result, default=_default))


def _default(o):
    if isinstance(o, (set, frozenset, tuple)):
        return list(o)
    if hasattr(o, "item"):
        return o.item()
    return str(o)
