"""Command-line interface.

    python -m ipsec_xray.cli analyze capture.pcap [--profile enterprise] [--json out.json] [--html out.html] [--pdf out.pdf] [--exec]
    python -m ipsec_xray.cli samples                       # list bundled scenario captures
    python -m ipsec_xray.cli batch samples/ --out reports/  # analyze a directory
    python -m ipsec_xray.cli serve [--port 8000]
    python -m ipsec_xray.cli live --iface eth0 | --sample enterprise_cbc_sha256_natt --speed 5   # terminal live view
    python -m ipsec_xray.cli train / generate
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SEV_ICON = {"critical": "!!", "high": "! ", "medium": "~ ", "low": "- ", "info": "i "}


def _print_summary(r: dict) -> None:
    a, f = r["assessment"], r["facts"]
    s = f["summary"]
    print(f"\nIPsec X-Ray  |  {r['name']}  |  profile: {a['profile_label']}")
    print("=" * 78)
    print(f"Security score : {a['score']:>5}/100   Grade: {a['grade']}" + (f"  (capped by {', '.join(a['grade_cap']['reason'])})" if a.get("grade_cap") else ""))
    print(f"Risk score     : {a['risk_score']:>5}/100   {a['risk_level']} exposure")
    print(f"AI confidence  : {a['ai_confidence']:>5}%     tiers: {a['tiers'].get('observed_pct')}% observed / {a['tiers'].get('inferred_pct')}% inferred / {a['tiers'].get('unknown_pct')}% unknown")
    print(f"Capture        : {f['capture']['packets']} pkts, {f['capture']['duration']} s, {f['capture']['ike_sa_count']} IKE SA, {f['capture']['tunnel_count']} tunnel(s)")
    print(f"IKE            : {s['primary_ike']}")
    print(f"ESP            : {s['primary_esp']}")
    print(f"Mode / traffic : {s['primary_mode']} / {s['primary_traffic']}   PFS: {s['pfs']}")
    print("-" * 78)
    print("Domain scores  : " + "  ".join(f"{v['label'].split(' ')[0]} {v['score']:g}/{v['cap']}" for v in a["domains"].values()))
    print("-" * 78)
    shown = [x for x in a["findings"] if x["severity"] != "info"]
    for x in shown[:25]:
        print(f" {SEV_ICON[x['severity']]} {x['severity']:8s} {x['id']:9s} [{x['tier']}{'' if x['tier'] == 'Observed' else f' {x['confidence']}'}] {x['message'][:100]}")
    infos = len(a["findings"]) - len(shown)
    print(f" ... {infos} informational notes, {a['counts']['pass']} checks passed, {a['counts']['na']} not applicable")
    print("-" * 78)
    print("Top actions:")
    for k, t in enumerate(a["top_actions"][:5], 1):
        print(f" {k}. [{t['severity']}] {t['id']} - {t['fix']}")
    print(f"Timing: {r['timing']['total_s']} s\n")


def cmd_analyze(args):
    from .pipeline import analyze_file
    from .report.render import render_html, render_pdf
    r = analyze_file(args.pcap, args.profile, limit=args.limit)
    if not args.quiet:
        _print_summary(r)
    kind = "executive" if args.exec else "technical"
    if args.json:
        with open(args.json, "w") as f:
            json.dump(r, f, indent=2)
        print("wrote", args.json)
    if args.html:
        with open(args.html, "w") as f:
            f.write(render_html(r, kind))
        print("wrote", args.html)
    if args.pdf:
        with open(args.pdf, "wb") as f:
            f.write(render_pdf(r, kind))
        print("wrote", args.pdf)
    return 0 if r["assessment"]["grade"] in ("A+", "A", "B") or not args.fail_below else 2


def cmd_samples(args):
    man_path = os.path.join(ROOT, "samples", "manifest.json")
    if not os.path.exists(man_path):
        print("no samples yet - run: python -m ipsec_xray.testbed.generate")
        return 1
    with open(man_path) as f:
        man = json.load(f)
    for name, t in man.items():
        print(f"{name:40s} IKEv{t['ike_version']}  expected {'/'.join(t['expected_grade']):6s} {t['description'][:80]}")
    return 0


def cmd_batch(args):
    from .pipeline import analyze_file
    from .report.render import render_html, render_pdf
    os.makedirs(args.out, exist_ok=True)
    files = sorted(glob.glob(os.path.join(args.directory, "*.pcap")) + glob.glob(os.path.join(args.directory, "*.pcapng")))
    rows = []
    for p in files:
        r = analyze_file(p, args.profile)
        base = os.path.join(args.out, os.path.splitext(os.path.basename(p))[0])
        with open(base + ".json", "w") as f:
            json.dump(r, f)
        with open(base + ".html", "w") as f:
            f.write(render_html(r))
        if args.pdf:
            with open(base + ".pdf", "wb") as f:
                f.write(render_pdf(r))
        a = r["assessment"]
        rows.append((os.path.basename(p), a["score"], a["grade"], a["risk_score"], a["counts"]["critical"], a["counts"]["high"]))
        print(f"{os.path.basename(p):40s} {a['score']:6.1f} {a['grade']:2s} risk {a['risk_score']:5.1f}  crit {a['counts']['critical']} high {a['counts']['high']}")
    with open(os.path.join(args.out, "summary.csv"), "w") as f:
        f.write("file,score,grade,risk,critical,high\n")
        for row in rows:
            f.write(",".join(str(x) for x in row) + "\n")
    print("reports in", args.out)
    return 0


def cmd_serve(args):
    import uvicorn
    uvicorn.run("ipsec_xray.api.app:app", host=args.host, port=args.port, reload=False, log_level="info")
    return 0


def cmd_live(args):
    """Terminal live mode: Wireshark-style packet lines + alerts + rolling grade (no browser needed)."""
    import time
    from .live.engine import LiveAnalyzer, make_source
    from .live.sources import can_sniff
    a = LiveAnalyzer(profile=args.profile, snapshot_interval=args.interval)
    last = {"grade": None}

    def on_event(e):
        if e["type"] == "packets" and not args.quiet:
            for r in e["rows"]:
                print(f"{r['n']:>7} {r['t']:>10.4f} {r['src']:>24} -> {r['dst']:<24} {r['proto']:<8} {r['len']:>5}  {r['info']}")
        elif e["type"] == "alert":
            al = e["alert"]
            print(f"### {SEV_ICON.get(al['severity'], '  ')} [{al['severity'].upper()}] {al['id']}: {al['title']}" + (f"  ({al['subject']})" if al["subject"] else ""), file=sys.stderr)
        elif e["type"] == "snapshot":
            g = e["snapshot"]["assessment"]
            if (g["grade"], g["score"]) != last["grade"]:
                last["grade"] = (g["grade"], g["score"])
                print(f"=== live grade {g['grade']} ({g['score']}/100), risk {g['risk_level']}, {len(e['snapshot']['tunnels'])} tunnel(s), "
                      f"{len(e['snapshot']['ike'])} IKE SA(s) - recomputed in {e['snapshot']['computed_in_ms']} ms", file=sys.stderr)

    a.add_listener(on_event)
    if args.iface:
        ok, why = can_sniff()
        if not ok:
            print(f"cannot capture on {args.iface}: {why}", file=sys.stderr)
            return 2
        src = make_source("interface", a.on_frame, iface=args.iface)
    else:
        path = args.pcap
        if args.sample:
            with open(os.path.join(ROOT, "samples", "manifest.json")) as f:
                man = json.load(f)
            path = os.path.join(ROOT, "samples", man[args.sample]["file"])
        src = make_source("replay", a.on_frame, path=path, speed=args.speed, loop=args.loop)
    a.start(src)
    try:
        while a.running and (args.duration <= 0 or time.time() - a.started_at < args.duration):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    a.stop()
    if args.save:
        n = a.save_pcap(args.save)
        print(f"saved {n} frames to {args.save}", file=sys.stderr)
    if a.snapshot:
        g = a.snapshot["assessment"]
        print(f"\nfinal: grade {g['grade']} ({g['score']}/100), {a.index} packets, {len(a.alerts)} alerts", file=sys.stderr)
    return 0


def cmd_train(args):
    from .ml.train import main as train_main
    argv = ["--flows-per-class", str(args.flows_per_class)]
    if getattr(args, "real", None):
        argv += ["--real", args.real]
    train_main(argv)
    return 0


def cmd_generate(args):
    from .testbed.generate import main as gen_main
    gen_main([])
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ipsec-xray", description="IPsec X-Ray - passive IPsec VPN analyzer and security assessment")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze one capture")
    a.add_argument("pcap")
    a.add_argument("--profile", default="baseline", choices=["baseline", "enterprise", "government", "pqc_ready"])
    a.add_argument("--json")
    a.add_argument("--html")
    a.add_argument("--pdf")
    a.add_argument("--exec", action="store_true", help="executive report instead of technical")
    a.add_argument("--limit", type=int, default=None, help="only read the first N packets")
    a.add_argument("--quiet", action="store_true")
    a.add_argument("--fail-below", action="store_true", help="exit code 2 when grade is worse than B (CI use)")
    a.set_defaults(fn=cmd_analyze)
    s = sub.add_parser("samples", help="list bundled sample captures")
    s.set_defaults(fn=cmd_samples)
    b = sub.add_parser("batch", help="analyze every pcap in a directory")
    b.add_argument("directory")
    b.add_argument("--out", default="reports")
    b.add_argument("--profile", default="baseline")
    b.add_argument("--pdf", action="store_true")
    b.set_defaults(fn=cmd_batch)
    sv = sub.add_parser("serve", help="run API + dashboard")
    sv.add_argument("--host", default="0.0.0.0")
    sv.add_argument("--port", type=int, default=8000)
    sv.set_defaults(fn=cmd_serve)
    lv = sub.add_parser("live", help="real-time analysis in the terminal (interface, sample replay or pcap replay)")
    lsrc = lv.add_mutually_exclusive_group(required=True)
    lsrc.add_argument("--iface", help="capture interface (needs CAP_NET_RAW)")
    lsrc.add_argument("--sample", help="replay a bundled sample")
    lsrc.add_argument("--pcap", help="replay a pcap file")
    lv.add_argument("--speed", type=float, default=1.0)
    lv.add_argument("--loop", action="store_true")
    lv.add_argument("--profile", default="baseline")
    lv.add_argument("--interval", type=float, default=2.0, help="seconds between re-assessments")
    lv.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = until source ends / Ctrl+C)")
    lv.add_argument("--save", help="write the captured frames to this pcap on exit")
    lv.add_argument("--quiet", action="store_true", help="alerts and grades only, no packet lines")
    lv.set_defaults(fn=cmd_live)
    t = sub.add_parser("train", help="(re)train the ML models")
    t.add_argument("--flows-per-class", type=int, default=200)
    t.add_argument("--real", metavar="DIR", help="labelled real captures (*.pcap + *.json) to mix into training")
    t.set_defaults(fn=cmd_train)
    g = sub.add_parser("generate", help="generate the sample scenario captures")
    g.set_defaults(fn=cmd_generate)
    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
