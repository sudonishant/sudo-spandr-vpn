"""Train the three ML models on simulated-but-physically-correct ESP flows.

    python -m ipsec_xray.ml.train [--flows-per-class 220] [--out models]

Models (scikit-learn RandomForest + probability calibration):
  traffic_rf.joblib : application class inside the tunnel (8 classes)
  cipher_rf.joblib  : cipher framing group (overhead/block) from length statistics
  mode_rf.joblib    : tunnel vs transport
"""
from __future__ import annotations

import argparse
import json
import os
import random
import time

import joblib
import numpy as np
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from ..analysis.features import CIPHER_FEATURE_NAMES, TRAFFIC_FEATURE_NAMES, cipher_features, traffic_features
from ..analysis.physics import ANCHORS, CANDIDATES, inner_interval
from .simulate import TRAFFIC_CLASSES, frame_esp, simulate

DURATIONS = {"voip": (8, 35), "video": (5, 20), "web": (12, 60), "email": (15, 60), "chat": (30, 150), "icmp": (8, 60),
             "file": (2, 12), "ssh": (15, 60)}
MAX_EVENTS = 4000


def framing_key(c) -> str:
    return f"o{c.overhead}_b{c.block}"


def mode_features(total_lengths: list[int]) -> np.ndarray:
    base = cipher_features(total_lengths)
    lps = [t - 8 for t in total_lengths if t > 8]
    extra = []
    if lps:
        from collections import Counter
        cnt = Counter(lps)
        top = [lp for lp, _ in sorted(cnt.items(), key=lambda kv: -kv[1])[:8]]
        for c in CANDIDATES:
            for mode in ("tunnel", "transport"):
                hits = 0
                for lp in top:
                    lo, hi = inner_interval(lp, c)
                    if any(lo <= a <= hi for a in ANCHORS[mode]):
                        hits += 1
                extra.append(hits / max(len(top), 1))
        extra.append(min(lps))
    else:
        extra = [0.0] * (2 * len(CANDIDATES) + 1)
    return np.concatenate([base, np.array(extra, dtype=float)])


MODE_FEATURE_NAMES = CIPHER_FEATURE_NAMES + [f"anch_{c.key}_{m}" for c in CANDIDATES for m in ("tunnel", "transport")] + ["min_lp2"]


def make_dataset(flows_per_class: int, seed: int = 7):
    rng = random.Random(seed)
    Xt, yt, Xc, yc, Xm, ym = [], [], [], [], [], []
    t0 = time.time()
    for cls in TRAFFIC_CLASSES:
        lo, hi = DURATIONS[cls]
        for i in range(flows_per_class):
            dur = rng.uniform(lo, hi)
            ipver = 6 if rng.random() < 0.2 else 4
            ev = simulate(cls, dur, seed=rng.randrange(1 << 30), ipver=ipver)
            if len(ev) > MAX_EVENTS:
                start = rng.randrange(0, len(ev) - MAX_EVENTS)
                ev = ev[start:start + MAX_EVENTS]
            if len(ev) < 4:
                continue
            cand = rng.choices(CANDIDATES, weights=[c.prior for c in CANDIDATES])[0]
            mode = "tunnel" if rng.random() < 0.75 else "transport"
            esp = frame_esp(ev, cand, mode, ipver, tfc=rng.random() < 0.03, loss=rng.choice([0, 0, 0.005, 0.02]), seed=rng.randrange(1 << 30))
            if len(esp) < 3:
                continue
            Xt.append(traffic_features(esp))
            yt.append(cls)
            lens = [e[2] for e in esp]
            Xc.append(cipher_features(lens))
            yc.append(framing_key(cand))
            Xm.append(mode_features(lens))
            ym.append(mode)
        print(f"  simulated {cls:6s} x{flows_per_class}  ({time.time() - t0:.1f}s)", flush=True)
    return (np.array(Xt), np.array(yt)), (np.array(Xc), np.array(yc)), (np.array(Xm), np.array(ym))


def load_real(directory: str):
    """Labelled real captures: every ``*.pcap`` with a sidecar ``*.json`` holding ``traffic`` (and optionally
    ``esp_framing`` = o<overhead>_b<block> and ``mode``). Flow features are extracted exactly as at inference time,
    so real strongSwan captures from ``testbed/strongswan/capture.sh`` can be mixed with the simulated corpus."""
    from ..analysis.session import build_session, pair_flows
    from ..pcap.reader import read_packets
    Xt, yt, Xc, yc, Xm, ym = [], [], [], [], [], []
    for fn in sorted(os.listdir(directory)):
        if not fn.lower().endswith((".pcap", ".pcapng", ".cap")):
            continue
        side = os.path.splitext(os.path.join(directory, fn))[0] + ".json"
        if not os.path.exists(side):
            continue
        with open(side) as f:
            label = json.load(f)
        sess = build_session(read_packets(os.path.join(directory, fn)))
        for t in pair_flows(sess):
            flows = t["flows"]
            if not flows or t.get("protocol") != "ESP":
                continue
            init = t.get("initiator") or flows[0].src
            merged = sorted(((ts, "up" if fl.src == init else "down", ln) for fl in flows for ts, ln, _ in fl.pkts), key=lambda e: e[0])
            if len(merged) < 5:
                continue
            lens = [e[2] for e in merged]
            traffic = label.get("traffic")
            if traffic in TRAFFIC_CLASSES:
                Xt.append(traffic_features(merged)); yt.append(traffic)
            if label.get("esp_framing"):
                Xc.append(cipher_features(lens)); yc.append(label["esp_framing"])
            if label.get("mode") in ("tunnel", "transport"):
                Xm.append(mode_features(lens)); ym.append(label["mode"])
        print(f"  real capture {fn}: {len(yt)} traffic / {len(yc)} cipher / {len(ym)} mode flows so far", flush=True)
    return (np.array(Xt), np.array(yt)), (np.array(Xc), np.array(yc)), (np.array(Xm), np.array(ym))


def _concat(sim, real):
    (Xs, ys), (Xr, yr) = sim, real
    if len(yr) == 0:
        return Xs, ys
    return np.concatenate([Xs, Xr]), np.concatenate([ys, yr])


def fit(X, y, n_estimators=300, seed=1):
    from collections import Counter
    min_count = min(Counter(y.tolist()).values())
    if min_count < 6:
        raise SystemExit(f"class with only {min_count} flows - increase --flows-per-class or add more labelled captures")
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=seed, stratify=y)
    base = RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=1, n_jobs=-1, random_state=seed, class_weight="balanced")
    clf = CalibratedClassifierCV(base, cv=3, method="sigmoid")
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    acc = accuracy_score(yte, pred)
    rep = classification_report(yte, pred, output_dict=True, zero_division=0)
    # refit on everything for the shipped model
    final = CalibratedClassifierCV(RandomForestClassifier(n_estimators=n_estimators, n_jobs=-1, random_state=seed, class_weight="balanced"),
                                   cv=3, method="sigmoid")
    final.fit(X, y)
    return final, acc, rep


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--flows-per-class", type=int, default=220)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "..", "models"))
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--real", metavar="DIR", help="directory of labelled real captures (*.pcap + *.json sidecar) to mix into training")
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    print("Simulating training flows ...")
    (Xt, yt), (Xc, yc), (Xm, ym) = make_dataset(args.flows_per_class, args.seed)
    n_real = 0
    if args.real:
        print(f"Loading labelled real captures from {args.real} ...")
        real_t, real_c, real_m = load_real(args.real)
        n_real = int(len(real_t[1]))
        Xt, yt = _concat((Xt, yt), real_t)
        Xc, yc = _concat((Xc, yc), real_c)
        Xm, ym = _concat((Xm, ym), real_m)
    import sklearn
    meta = {"trained_at": time.strftime("%Y-%m-%d %H:%M:%S"), "flows": int(len(yt)), "flows_per_class": args.flows_per_class,
            "real_flows": n_real, "sklearn": sklearn.__version__,
            "note": ("Trained on simulated flows framed with the exact ESP length model" + (f" plus {n_real} labelled real flows" if n_real else "")
                     + ". For production use, record captures with testbed/strongswan/capture.sh and retrain with "
                       "`python -m ipsec_xray.ml.train --real testbed/strongswan/pcaps`."),
            "models": {}}
    for name, (X, y), names in (("traffic", (Xt, yt), TRAFFIC_FEATURE_NAMES), ("cipher", (Xc, yc), CIPHER_FEATURE_NAMES),
                                ("mode", (Xm, ym), MODE_FEATURE_NAMES)):
        print(f"Training {name} model on {len(y)} flows / {len(names)} features ...", flush=True)
        clf, acc, rep = fit(X, y, seed=args.seed)
        path = os.path.join(args.out, f"{name}_rf.joblib")
        joblib.dump(clf, path, compress=3)
        classes = sorted(set(y.tolist()))
        meta["models"][name] = {"file": os.path.basename(path), "holdout_accuracy": round(float(acc), 4), "classes": classes,
                                "n_features": len(names),
                                "per_class_f1": {k: round(v["f1-score"], 3) for k, v in rep.items() if k in classes}}
        print(f"  holdout accuracy = {acc:.4f}")
    with open(os.path.join(args.out, "meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
    print("Saved models to", os.path.abspath(args.out))


if __name__ == "__main__":
    main()
