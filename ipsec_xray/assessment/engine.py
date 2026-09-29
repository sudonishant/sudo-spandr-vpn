"""Rule engine: evaluates the YAML check catalogue against a facts document and produces score, grade, risk, threats."""
from __future__ import annotations

import ast
import os
import re
from functools import lru_cache
from typing import Any

import yaml

HERE = os.path.dirname(__file__)
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "none": 5}


# --------------------------------------------------------------------------- safe expression evaluator
class _Undefined:
    def __bool__(self):
        return False

    def __repr__(self):
        return "None"


_SAFE_FUNCS = {
    "len": lambda x: len(x) if x is not None else 0,
    "max": lambda *a: max(*a) if a and not (len(a) == 1 and not a[0]) else 0,
    "min": lambda *a: min(*a) if a and not (len(a) == 1 and not a[0]) else 0,
    "abs": abs, "round": round, "any": any, "all": all, "sum": sum, "str": str, "int": int, "float": float,
    "get": lambda d, k, default=None: (d.get(k, default) if isinstance(d, dict) else default),
    "subset": lambda a, b: set(a or []) <= set(b or []),
    "startswith": lambda s, p: isinstance(s, str) and s.startswith(p),
    "contains": lambda a, x: (x in a) if a is not None else False,
}


class SafeEval(ast.NodeVisitor):
    def __init__(self, scope: dict):
        self.scope = scope

    def eval(self, expr: str):
        tree = ast.parse(expr, mode="eval")
        return self.visit(tree.body)

    def generic_visit(self, node):
        raise ValueError(f"unsupported expression element: {type(node).__name__}")

    def visit_Constant(self, n):
        return n.value

    def visit_Name(self, n):
        if n.id == "_":
            return self.scope
        if n.id in ("True", "False", "None"):
            return {"True": True, "False": False, "None": None}[n.id]
        if n.id in self.scope:
            return self.scope[n.id]
        if n.id in _SAFE_FUNCS:
            return _SAFE_FUNCS[n.id]
        return None

    def visit_Attribute(self, n):
        base = self.visit(n.value)
        if isinstance(base, dict):
            return base.get(n.attr)
        return None

    def visit_Subscript(self, n):
        base = self.visit(n.value)
        idx = self.visit(n.slice)
        try:
            return base[idx]
        except Exception:
            return None

    def visit_List(self, n):
        return [self.visit(e) for e in n.elts]

    def visit_Tuple(self, n):
        return tuple(self.visit(e) for e in n.elts)

    def visit_UnaryOp(self, n):
        v = self.visit(n.operand)
        if isinstance(n.op, ast.Not):
            return not v
        if isinstance(n.op, ast.USub):
            return -v
        raise ValueError("unsupported unary op")

    def visit_BoolOp(self, n):
        if isinstance(n.op, ast.And):
            for v in n.values:
                r = self.visit(v)
                if not r:
                    return False
            return True
        for v in n.values:
            r = self.visit(v)
            if r:
                return True
        return False

    def visit_BinOp(self, n):
        a, b = self.visit(n.left), self.visit(n.right)
        if a is None or b is None:
            return None
        if isinstance(n.op, ast.Add):
            return a + b
        if isinstance(n.op, ast.Sub):
            return a - b
        if isinstance(n.op, ast.Mult):
            return a * b
        if isinstance(n.op, ast.Div):
            return a / b if b else None
        if isinstance(n.op, ast.Mod):
            return a % b if b else None
        raise ValueError("unsupported binary op")

    def visit_Compare(self, n):
        left = self.visit(n.left)
        for op, comp in zip(n.ops, n.comparators):
            right = self.visit(comp)
            try:
                if isinstance(op, ast.Eq):
                    ok = left == right
                elif isinstance(op, ast.NotEq):
                    ok = left != right
                elif isinstance(op, ast.In):
                    ok = right is not None and left in right
                elif isinstance(op, ast.NotIn):
                    ok = right is None or left not in right
                elif isinstance(op, ast.Is):
                    ok = left is right
                elif isinstance(op, ast.IsNot):
                    ok = left is not right
                elif left is None or right is None:
                    ok = False
                elif isinstance(op, ast.Lt):
                    ok = left < right
                elif isinstance(op, ast.LtE):
                    ok = left <= right
                elif isinstance(op, ast.Gt):
                    ok = left > right
                elif isinstance(op, ast.GtE):
                    ok = left >= right
                else:
                    raise ValueError("unsupported comparison")
            except TypeError:
                ok = False
            if not ok:
                return False
            left = right
        return True

    def visit_IfExp(self, n):
        return self.visit(n.body) if self.visit(n.test) else self.visit(n.orelse)

    def visit_Call(self, n):
        fn = self.visit(n.func)
        if fn is None or not callable(fn) or fn not in _SAFE_FUNCS.values():
            raise ValueError("call to non-whitelisted function")
        args = [self.visit(a) for a in n.args]
        kwargs = {k.arg: self.visit(k.value) for k in n.keywords}
        return fn(*args, **kwargs)


def evaluate(expr: str, scope: dict, default=None):
    try:
        return SafeEval(scope).eval(expr)
    except Exception:
        return default


# --------------------------------------------------------------------------- catalogue loading
@lru_cache(maxsize=1)
def load_catalog() -> dict:
    with open(os.path.join(HERE, "checks.yaml")) as f:
        checks = yaml.safe_load(f)
    with open(os.path.join(HERE, "threats.yaml")) as f:
        threats = yaml.safe_load(f)
    with open(os.path.join(HERE, "profiles.yaml")) as f:
        profiles = yaml.safe_load(f)
    return {"checks": checks["checks"], "defaults": checks["defaults"], "threats": threats["threats"],
            "trigger_likelihood": threats["trigger_likelihood"], "profiles": profiles["profiles"], "scoring": profiles["scoring"]}


def _severity(check: dict, profile: str, cat: dict) -> str:
    """Severity of a check under a profile; profiles may inherit (pqc_ready -> government)."""
    sbp = check.get("severity_by_profile", {})
    seen = set()
    while profile and profile not in seen:
        if profile in sbp:
            return sbp[profile]
        seen.add(profile)
        profile = cat["profiles"].get(profile, {}).get("inherits")
    return check.get("severity", "info")


def list_checks(profile: str = "baseline") -> list[dict]:
    cat = load_catalog()
    out = []
    for c in cat["checks"]:
        sev = _severity(c, profile, cat)
        out.append({"id": c["id"], "family": c["family"], "title": c["title"], "scope": c["scope"], "severity": sev, "domain": c["domain"],
                    "ref": c.get("ref", ""), "threat": c.get("threat", []), "fix": c.get("fix", ""), "when": c["when"]})
    return out


def list_threats() -> list[dict]:
    return load_catalog()["threats"]


def list_profiles() -> dict:
    return {k: {"label": v["label"], "description": v["description"]} for k, v in load_catalog()["profiles"].items()}


# --------------------------------------------------------------------------- helpers
_FMT = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_.]*)\}")


def _fmt(msg: str, scope: dict) -> str:
    def rep(m):
        v = evaluate(m.group(1), scope, default="?")
        if isinstance(v, float):
            v = round(v, 3)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            v = [x.get("vendor") or x.get("value") or x for x in v]
        return str(v)
    return _FMT.sub(rep, msg)


def _subject(scope_name: str, inst: dict) -> str:
    if scope_name == "ike":
        return f"IKEv{inst.get('version')} SA {inst.get('initiator')} -> {inst.get('responder')}"
    if scope_name == "tunnel":
        p = inst.get("peers", ["?", "?"])
        return f"{inst.get('protocol')} tunnel {p[0]} <-> {p[1]}"
    return "capture"


def grade_for(score: float, grades) -> str:
    for g, thr in grades:
        if score >= thr:
            return g
    return "F"


def risk_level(risk: float) -> str:
    return "Critical" if risk >= 75 else "High" if risk >= 50 else "Moderate" if risk >= 25 else "Low"


# --------------------------------------------------------------------------- main
def assess(facts: dict, profile: str = "baseline") -> dict:
    cat = load_catalog()
    if profile not in cat["profiles"]:
        profile = "baseline"
    prof = dict(cat["profiles"][profile])
    scoring = cat["scoring"]
    pen_by_sev = cat["defaults"]["penalty_by_severity"]
    risk_by_sev = cat["defaults"]["risk_weight_by_severity"]

    scopes = {
        "ike": [i for i in facts.get("ike", []) if i.get("complete", True)],
        "tunnel": facts.get("tunnels", []),
        "capture": [facts.get("capture", {})],
    }
    findings: list[dict] = []
    results: list[dict] = []
    domain_pen = {d: 0.0 for d in scoring["domains"]}
    risk_raw = 0.0
    triggers: dict[str, list] = {}

    for c in cat["checks"]:
        sev = _severity(c, profile, cat)
        res = {"id": c["id"], "family": c["family"], "title": c["title"], "severity": sev, "domain": c["domain"], "scope": c["scope"],
               "status": "pass", "count": 0, "ref": c.get("ref", ""), "fix": c.get("fix", "")}
        if sev == "none":
            res["status"] = "na"
            results.append(res)
            continue
        instances = scopes.get(c["scope"], [])
        applicable = 0
        best_pen = 0.0
        best_risk = 0.0
        for inst in instances:
            scope = dict(inst)
            scope["profile"] = prof
            scope["_capture"] = facts.get("capture", {})
            if c.get("requires") and not evaluate(c["requires"], scope, default=False):
                continue
            applicable += 1
            if not evaluate(c["when"], scope, default=False):
                continue
            tier = evaluate(c["tier"], scope, default="Observed") if c.get("tier") else "Observed"
            conf = evaluate(c["confidence"], scope, default=1.0) if c.get("confidence") else 1.0
            try:
                conf = float(conf if conf is not None else 1.0)
            except (TypeError, ValueError):
                conf = 1.0
            if tier not in ("Observed", "Inferred", "Unknown"):
                tier = "Observed"
            base_pen = evaluate(c["penalty_expr"], scope, default=None) if c.get("penalty_expr") else None
            if base_pen is None:
                base_pen = c.get("penalty", pen_by_sev.get(sev, 0))
            weight = 1.0 if tier == "Observed" else (conf if tier == "Inferred" else 0.0)
            pen = float(base_pen) * weight
            rk = float(risk_by_sev.get(sev, 0)) * weight
            f = {"id": c["id"], "title": c["title"], "family": c["family"], "severity": sev, "domain": c["domain"], "tier": tier,
                 "confidence": round(conf, 3), "scope": c["scope"], "subject": _subject(c["scope"], inst),
                 "message": _fmt(c.get("message", c["title"]), scope), "fix": c.get("fix", ""), "ref": c.get("ref", ""),
                 "threat": c.get("threat", []), "penalty": round(pen, 2)}
            findings.append(f)
            res["count"] += 1
            best_pen = max(best_pen, pen)
            best_risk = max(best_risk, rk)
            for th in c.get("threat", []):
                triggers.setdefault(th, []).append((c["id"], sev, weight))
        if applicable == 0:
            res["status"] = "na"
        elif res["count"] > 0:
            res["status"] = "info" if sev == "info" else "fail"
        results.append(res)
        if res["count"] > 0:
            domain_pen[c["domain"]] += best_pen       # one penalty per check (worst instance)
            risk_raw += best_risk

    domains = {}
    score = 100.0
    for d, cap in scoring["domains"].items():
        p = min(cap, domain_pen[d])
        domains[d] = {"label": scoring["domain_labels"][d], "cap": cap, "penalty": round(p, 2), "score": round(cap - p, 2)}
        score -= p
    score = max(0.0, round(score, 1))
    grade = grade_for(score, scoring["grades"])
    # grade caps: a confirmed critical finding can never be better than D, a confirmed high never better than B
    grade_cap = None
    order = [g for g, _ in scoring["grades"]]
    confirmed = [f for f in findings if f["tier"] == "Observed" or (f["tier"] == "Inferred" and f["confidence"] >= 0.75)]
    if any(f["severity"] == "critical" for f in confirmed):
        cap, why = "D", [f["id"] for f in confirmed if f["severity"] == "critical"]
    elif any(f["severity"] == "high" for f in confirmed):
        cap, why = "B", [f["id"] for f in confirmed if f["severity"] == "high"]
    else:
        cap, why = None, []
    if cap and order.index(grade) < order.index(cap):
        grade_cap = {"grade": cap, "reason": sorted(set(why))[:6]}
        grade = cap
    risk = min(100.0, round(risk_raw, 1))

    # threat matrix
    tl = cat["trigger_likelihood"]
    threats = []
    for th in cat["threats"]:
        trig = triggers.get(th["id"], [])
        like = th["base_likelihood"]
        for cid, sev, w in trig:
            if w > 0:
                like = max(like, tl.get(sev, 1))
        sc = like * th["impact"]
        threats.append({"id": th["id"], "title": th["title"], "actor": th["actor"], "description": th["description"],
                        "impact": th["impact"], "likelihood": like, "score": sc,
                        "level": "Critical" if sc >= 20 else "High" if sc >= 12 else "Moderate" if sc >= 6 else "Low",
                        "triggered_by": sorted(set(cid for cid, _, w in trig if w > 0))})
    threats.sort(key=lambda t: -t["score"])

    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), -f["penalty"], f["id"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in ("critical", "high", "medium", "low", "info")}
    counts["pass"] = sum(1 for r in results if r["status"] == "pass")
    counts["na"] = sum(1 for r in results if r["status"] == "na")
    counts["fail"] = sum(1 for r in results if r["status"] == "fail")
    seen = set()
    actions = []
    for f in findings:
        if f["severity"] in ("critical", "high", "medium") and f["id"] not in seen and f["tier"] != "Unknown":
            seen.add(f["id"])
            actions.append({"id": f["id"], "severity": f["severity"], "title": f["title"], "fix": f["fix"], "penalty": f["penalty"]})
        if len(actions) >= 8:
            break
    summary = facts.get("summary", {})
    return {
        "profile": profile, "profile_label": prof["label"], "profile_description": prof["description"],
        "score": score, "grade": grade, "grade_cap": grade_cap, "risk_score": risk, "risk_level": risk_level(risk),
        "domains": domains, "findings": findings, "check_results": results, "counts": counts, "threats": threats,
        "top_actions": actions, "ai_confidence": summary.get("ai_confidence", 0.0), "tiers": summary.get("tiers", {}),
        "checks_total": len(results),
    }
