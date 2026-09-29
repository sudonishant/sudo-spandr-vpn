"""SQLite persistence for analysis results."""
from __future__ import annotations

import json
import os
import sqlite3
import threading

DATA_DIR = os.environ.get("IPSEC_XRAY_DATA", os.path.join(os.path.dirname(__file__), "..", "..", "data"))


class Store:
    def __init__(self, path: str | None = None):
        os.makedirs(DATA_DIR, exist_ok=True)
        self.path = path or os.path.join(DATA_DIR, "results.db")
        self._lock = threading.Lock()
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS results (
                id TEXT PRIMARY KEY, name TEXT, created TEXT, profile TEXT, score REAL, grade TEXT, risk REAL,
                packets INTEGER, summary TEXT, doc TEXT)""")

    def _conn(self):
        c = sqlite3.connect(self.path, check_same_thread=False)
        c.row_factory = sqlite3.Row
        return c

    def put(self, result: dict) -> None:
        a, f = result["assessment"], result["facts"]
        summary = {"primary_ike": f["summary"].get("primary_ike"), "primary_esp": f["summary"].get("primary_esp"),
                   "primary_traffic": f["summary"].get("primary_traffic"), "ike_sa_count": f["capture"]["ike_sa_count"],
                   "tunnel_count": f["capture"]["tunnel_count"], "counts": a["counts"], "ai_confidence": a["ai_confidence"],
                   "duration": f["capture"]["duration"], "risk_level": a["risk_level"], "tiers": a.get("tiers", {})}
        with self._lock, self._conn() as c:
            c.execute("INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?,?,?,?,?)",
                      (result["id"], result["name"], result["created"], result["profile"], a["score"], a["grade"], a["risk_score"],
                       f["capture"]["packets"], json.dumps(summary), json.dumps(result)))

    def list(self, limit: int = 200) -> list[dict]:
        with self._conn() as c:
            rows = c.execute("SELECT id,name,created,profile,score,grade,risk,packets,summary FROM results ORDER BY created DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["summary"] = json.loads(d.pop("summary") or "{}")
            out.append(d)
        return out

    def get(self, rid: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT doc FROM results WHERE id=?", (rid,)).fetchone()
        return json.loads(row["doc"]) if row else None

    def delete(self, rid: str) -> bool:
        with self._lock, self._conn() as c:
            cur = c.execute("DELETE FROM results WHERE id=?", (rid,))
            return cur.rowcount > 0
