"""Report rendering: HTML (Jinja2) and PDF (reportlab) for executive and technical audiences."""
from __future__ import annotations

import io
import math
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")
_env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(["html"]))

GRADE_COLORS = {"A+": "#2E7D32", "A": "#2E7D32", "B": "#7CB342", "C": "#EF6C00", "D": "#E64A19", "F": "#C62828"}


def grade_color(g: str) -> str:
    return GRADE_COLORS.get(g, "#607D8B")


def risk_color(r: float) -> str:
    return "#C62828" if r >= 75 else "#E64A19" if r >= 50 else "#EF6C00" if r >= 25 else "#2E7D32"


def gauge_svg(score: float, grade: str, size: int = 150) -> str:
    """Semi-circular gauge as inline SVG."""
    cx, cy, r = size / 2, size * 0.58, size * 0.42
    frac = max(0.0, min(1.0, score / 100.0))

    def arc(f0, f1, color, width):
        a0, a1 = math.pi * (1 - f0), math.pi * (1 - f1)
        x0, y0 = cx + r * math.cos(a0), cy - r * math.sin(a0)
        x1, y1 = cx + r * math.cos(a1), cy - r * math.sin(a1)
        large = 1 if (f1 - f0) > 0.5 else 0
        return f'<path d="M{x0:.1f},{y0:.1f} A{r:.1f},{r:.1f} 0 {large} 1 {x1:.1f},{y1:.1f}" stroke="{color}" stroke-width="{width}" fill="none" stroke-linecap="round"/>'
    svg = [f'<svg width="{size}" height="{size * 0.7:.0f}" viewBox="0 0 {size} {size * 0.7:.0f}" xmlns="http://www.w3.org/2000/svg">']
    svg.append(arc(0.0, 1.0, "#e6ebf1", 12))
    if frac > 0.005:
        svg.append(arc(0.0, frac, grade_color(grade), 12))
    svg.append(f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" font-family="Segoe UI, Arial" font-size="{size * 0.2:.0f}" font-weight="700" fill="{grade_color(grade)}">{grade}</text>')
    svg.append(f'<text x="{cx}" y="{cy + size * 0.1:.0f}" text-anchor="middle" font-family="Segoe UI, Arial" font-size="{size * 0.09:.0f}" fill="#5c6b7a">{score:g} / 100</text>')
    svg.append("</svg>")
    return "".join(svg)


def threat_matrix(threats: list[dict]) -> list[list[dict]]:
    rows = []
    for l in range(5, 0, -1):
        row = []
        for i in range(1, 6):
            sc = l * i
            color = "#FFCDD2" if sc >= 20 else "#FFE0B2" if sc >= 12 else "#FFF9C4" if sc >= 6 else "#E8F5E9"
            ids = [t["id"] for t in threats if t["likelihood"] == l and t["impact"] == i]
            row.append({"l": l, "i": i, "score": sc, "color": color, "ids": ids})
        rows.append(row)
    return rows


def narrative(result: dict) -> list[str]:
    f, a = result["facts"], result["assessment"]
    s = f.get("summary", {})
    out = []
    ike = [i for i in f.get("ike", []) if i.get("complete")]
    if ike:
        i = ike[0]
        out.append(f"<b>Key exchange:</b> IKEv{i['version']}{' ' + i['v1_mode'] + ' mode' if i.get('v1_mode') else ''} with {i['encr_label']}"
                   f"{'' if i.get('encr_aead') else ' / ' + str(i.get('integ'))} and {i.get('dh')} between {i['initiator']} and {i['responder']}"
                   f"{' (post-quantum hybrid: ' + ', '.join(i['pqc_groups']) + ')' if i.get('pqc_hybrid') else ''}.")
        if i.get("auth", {}).get("method"):
            out.append(f"<b>Authentication:</b> {i['auth']['method']} ({i['auth']['tier'].lower()}).")
    else:
        out.append("<b>Key exchange:</b> no complete IKE negotiation in the capture window (only ESP/AH data plane).")
    for t in f.get("tunnels", [])[:3]:
        fr = t["framing"]
        out.append(f"<b>Data plane {t['peers'][0]} &harr; {t['peers'][1]}:</b> {t['protocol']} framing matches <i>{fr['label']}</i> "
                   f"({fr['tier'].lower()}, confidence {fr['confidence']}), {t['mode']['value']} mode, carrying <i>{t['traffic']['label']}</i> "
                   f"(confidence {t['traffic']['confidence']}); PFS {t['pfs']['state']}; sequence numbers {'clean' if t['replay']['monotonic'] else 'anomalous'}.")
    crit = [x for x in a["findings"] if x["severity"] in ("critical", "high") and x["tier"] != "Unknown"]
    if crit:
        ids = sorted(set(x["id"] for x in crit))
        out.append(f"<b>Main weaknesses:</b> {len(ids)} critical/high checks fail ({', '.join(ids[:8])}{'...' if len(ids) > 8 else ''}).")
    else:
        out.append("<b>No critical or high-severity weakness</b> was found under this profile.")
    out.append(f"<b>Overall:</b> security score {a['score']}/100, grade <b>{a['grade']}</b>"
               f"{' (capped by ' + ', '.join(a['grade_cap']['reason']) + ')' if a.get('grade_cap') else ''}; risk exposure {a['risk_level'].lower()} ({a['risk_score']}); "
               f"{s.get('tiers', {}).get('unknown_pct', 0)}% of the assessed fields are honestly reported as Unknown.")
    return out


def render_html(result: dict, kind: str = "technical") -> str:
    a = result["assessment"]
    findings = a["findings"]
    if kind == "executive":
        findings = [x for x in findings if x["severity"] != "info"][:12]
    tpl = _env.get_template("report.html.j2")
    return tpl.render(r=result, f=result["facts"], a=a, kind=kind, gauge=gauge_svg(a["score"], a["grade"]),
                      grade_color=grade_color(a["grade"]), risk_color=risk_color(a["risk_score"]), narrative=narrative(result),
                      matrix=threat_matrix(a["threats"]), findings_shown=findings)


# --------------------------------------------------------------------------- PDF
def render_pdf(result: dict, kind: str = "technical") -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.graphics.shapes import Drawing, String, Wedge
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle, KeepTogether

    a, f = result["assessment"], result["facts"]
    styles = getSampleStyleSheet()
    H1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=18, textColor=colors.HexColor("#1F4E79"), alignment=TA_LEFT, spaceAfter=4)
    H2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=13, textColor=colors.HexColor("#1F4E79"), spaceBefore=12, spaceAfter=6)
    H3 = ParagraphStyle("h3", parent=styles["Heading3"], fontSize=10.5, textColor=colors.HexColor("#0070C0"), spaceBefore=8, spaceAfter=3)
    N = ParagraphStyle("n", parent=styles["Normal"], fontSize=8.6, leading=11)
    S = ParagraphStyle("s", parent=N, fontSize=7.6, leading=9.5, textColor=colors.HexColor("#546E7A"))
    C = ParagraphStyle("c", parent=N, fontSize=7.8, leading=9.8)
    K = ParagraphStyle("k", parent=N, fontSize=8.6, leading=13)

    def P(t, st=N):
        return Paragraph(str(t).replace("&harr;", "<->").replace("&mdash;", "-").replace("&rarr;", "->").replace("&middot;", "|"), st)

    def sev_color(s):
        return {"critical": "#C62828", "high": "#E64A19", "medium": "#EF6C00", "low": "#F9A825", "info": "#607D8B"}.get(s, "#607D8B")

    def table(data, widths, header=True, font=7.8, zebra=True):
        t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
        st = [("FONTSIZE", (0, 0), (-1, -1), font), ("VALIGN", (0, 0), (-1, -1), "TOP"),
              ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#CFD8E3")), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
              ("TOPPADDING", (0, 0), (-1, -1), 2.5), ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5)]
        if header:
            st += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF3F8")), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]
        if zebra:
            for r in range(1, len(data)):
                if r % 2 == 0:
                    st.append(("BACKGROUND", (0, r), (-1, r), colors.HexColor("#FAFBFD")))
        t.setStyle(TableStyle(st))
        return t

    def gauge():
        d = Drawing(120, 75)
        frac = max(0.0, min(1.0, a["score"] / 100))
        d.add(Wedge(60, 15, 52, 0, 180, yradius=52, fillColor=colors.HexColor("#E6EBF1"), strokeColor=None))
        if frac > 0.005:
            d.add(Wedge(60, 15, 52, 180 - 180 * frac, 180, yradius=52, fillColor=colors.HexColor(grade_color(a["grade"])), strokeColor=None))
        d.add(Wedge(60, 15, 38, 0, 180, yradius=38, fillColor=colors.white, strokeColor=None))
        d.add(String(60, 30, a["grade"], fontName="Helvetica-Bold", fontSize=22, fillColor=colors.HexColor(grade_color(a["grade"])), textAnchor="middle"))
        d.add(String(60, 17, f"{a['score']:g} / 100", fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#5C6B7A"), textAnchor="middle"))
        return d

    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=14 * mm, bottomMargin=14 * mm,
                            title=f"IPsec X-Ray {kind} report - {result['name']}", author="IPsec X-Ray")
    W = A4[0] - 32 * mm
    el = []
    title = "Executive Summary" if kind == "executive" else "Technical Report"
    head = Table([[[P(f"IPsec X-Ray - {title}", H1),
                     P(f"Capture: <b>{result['name']}</b> | Profile: <b>{a['profile_label']}</b> | Generated: {result['created']} | Engine v{result['version']}", S),
                     P(f"{f['capture']['packets']} packets, {f['capture']['duration']} s, {f['capture']['ike_sa_count']} IKE SA(s), {f['capture']['tunnel_count']} tunnel(s)", S)],
                    gauge()]], colWidths=[W - 130, 130])
    head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el.append(head)
    el.append(Spacer(1, 6))
    kp = [[P("<b>Security score</b>", S), P("<b>Grade</b>", S), P("<b>Risk score</b>", S), P("<b>AI confidence</b>", S), P("<b>Findings</b>", S)],
          [P(f"<font size=16 color='{grade_color(a['grade'])}'><b>{a['score']}</b></font> /100", K),
           P(f"<font size=16 color='{grade_color(a['grade'])}'><b>{a['grade']}</b></font>" + (f"<br/><font size=6.5 color='#78909C'>capped by {', '.join(a['grade_cap']['reason'])}</font>" if a.get("grade_cap") else ""), K),
           P(f"<font size=16 color='{risk_color(a['risk_score'])}'><b>{a['risk_score']}</b></font><br/><font size=6.5 color='#78909C'>{a['risk_level']} exposure</font>", K),
           P(f"<font size=16><b>{a['ai_confidence']}%</b></font>", K),
           P(f"<font size=16><b>{a['counts']['critical'] + a['counts']['high'] + a['counts']['medium'] + a['counts']['low']}</b></font><br/><font size=6.5 color='#78909C'>{a['counts']['critical']} crit | {a['counts']['high']} high | {a['counts']['medium']} med | {a['counts']['low']} low</font>", K)]]
    kt = Table(kp, colWidths=[W / 5] * 5)
    kt.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDE5EE")), ("INNERGRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#DDE5EE")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F4F6F9")), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    el.append(kt)
    tiers = a.get("tiers", {})
    el.append(Spacer(1, 4))
    el.append(P(f"Evidence tiers: <font color='#2E7D32'><b>{tiers.get('observed_pct', 0)}% observed</b></font>, "
                f"<font color='#EF6C00'><b>{tiers.get('inferred_pct', 0)}% inferred</b></font>, <font color='#607D8B'><b>{tiers.get('unknown_pct', 0)}% unknown</b></font> "
                f"- fields that cannot be recovered passively are reported as Unknown, never guessed.", S))

    el.append(P("1. What the capture shows", H2))
    for s_ in narrative(result):
        el.append(P("- " + s_.replace("<i>", "<i>").replace("</i>", "</i>"), N))

    el.append(P("2. Score breakdown", H2))
    rows = [["Domain", "Score", "Cap", "Penalty"]]
    for d, v in a["domains"].items():
        rows.append([v["label"], f"{v['score']:g}", str(v["cap"]), f"{v['penalty']:g}"])
    el.append(table(rows, [W * 0.55, W * 0.15, W * 0.15, W * 0.15]))

    el.append(P("3. Priority actions", H2))
    if a["top_actions"]:
        rows = [["#", "Severity", "Check", "Recommended fix"]]
        for k, t in enumerate(a["top_actions"], 1):
            rows.append([str(k), P(f"<font color='{sev_color(t['severity'])}'><b>{t['severity']}</b></font>", C), P(f"<b>{t['id']}</b> {t['title']}", C), P(t["fix"], C)])
        el.append(table(rows, [W * 0.05, W * 0.12, W * 0.33, W * 0.50]))
    else:
        el.append(P("No corrective actions required under this profile.", S))

    findings = a["findings"] if kind != "executive" else [x for x in a["findings"] if x["severity"] != "info"][:12]
    el.append(P("4. Findings" + (" (non-informational)" if kind == "executive" else ""), H2))
    rows = [["Severity", "ID", "Finding", "Subject", "Evidence", "Detail"]]
    for x in findings:
        rows.append([P(f"<font color='{sev_color(x['severity'])}'><b>{x['severity']}</b></font>", C), P(f"<b>{x['id']}</b>", C),
                     P(f"{x['title']}<br/><font size=6.5 color='#78909C'>{x['ref']}</font>", C), P(x["subject"], C),
                     P(f"{x['tier']}" + (f"<br/>conf {x['confidence']}" if x["tier"] != "Observed" else ""), C),
                     P(x["message"] + (f"<br/><font color='#1B5E20'>Fix: {x['fix']}</font>" if kind != "executive" else ""), C)])
    el.append(table(rows, [W * 0.085, W * 0.105, W * 0.2, W * 0.15, W * 0.085, W * 0.375]))

    el.append(P("5. Threat matrix", H2))
    m = threat_matrix(a["threats"])
    grid = [[P("L \\ I", S)] + [P(f"<b>I{i}</b>", S) for i in range(1, 6)]]
    for row in m:
        grid.append([P(f"<b>L{row[0]['l']}</b>", S)] + [P(" ".join(c["ids"]) or " ", S) for c in row])
    gt = Table(grid, colWidths=[W * 0.08] + [W * 0.11] * 5, rowHeights=[14] + [22] * 5)
    st = [("GRID", (0, 0), (-1, -1), 0.4, colors.white), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEF3F8")),
          ("BACKGROUND", (0, 1), (0, -1), colors.HexColor("#EEF3F8"))]
    for ri, row in enumerate(m, 1):
        for ci, c in enumerate(row, 1):
            st.append(("BACKGROUND", (ci, ri), (ci, ri), colors.HexColor(c["color"])))
    gt.setStyle(TableStyle(st))
    rows = [["ID", "Threat", "L", "I", "Level", "Triggered by"]]
    for t in a["threats"]:
        rows.append([t["id"], P(t["title"], C), str(t["likelihood"]), str(t["impact"]), t["level"], P(", ".join(t["triggered_by"]) or "-", S)])
    tt = table(rows, [W * 0.36 * 0.14, W * 0.36 * 0.46, W * 0.36 * 0.07, W * 0.36 * 0.07, W * 0.36 * 0.13, W * 0.36 * 0.13])
    side = Table([[gt, tt]], colWidths=[W * 0.64, W * 0.36])
    side.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP")]))
    el.append(side)

    if kind != "executive":
        el.append(PageBreak())
        el.append(P("6. Hidden-field inference (per tunnel)", H2))
        for t in f["tunnels"]:
            fr = t["framing"]
            block = [P(f"{t['protocol']} tunnel {t['peers'][0]} <-> {t['peers'][1]} - {t['packets']} packets, {t['bytes']} bytes, {t['duration']} s"
                       f"{', UDP-encapsulated' if t['udp_encap'] else ''}{', IPv6' if t['ipver'] == 6 else ''}", H3)]
            rows = [["Field", "Value", "Evidence"],
                    ["Cipher framing", P(f"<b>{fr['label']}</b>", C), P(f"{fr['tier']} conf {fr['confidence']} | IV {fr.get('iv')} + ICV {fr.get('icv')} B, block {fr.get('block')} B", C)],
                    ["Encapsulation mode", P(f"<b>{t['mode']['value']}</b>", C), P(f"{t['mode']['tier']} conf {t['mode']['confidence']}", C)],
                    ["Traffic inside", P(f"<b>{t['traffic']['label']}</b>", C), P(f"{t['traffic']['tier']} conf {t['traffic']['confidence']}" + (" | top-3: " + ", ".join(f"{c['label']} {c['p']}" for c in t['traffic']['top']) if t['traffic'].get('top') else ""), C)],
                    ["Perfect forward secrecy", P(f"<b>{t['pfs']['state']}</b>" + (f" ({t['pfs']['group_guess']})" if t['pfs'].get('group_guess') else ""), C), P(f"{t['pfs']['tier']} conf {t['pfs']['confidence']} | {t['pfs'].get('evidence', '')}", C)],
                    ["Anti-replay sequence", "monotonic" if t["replay"]["monotonic"] else "anomalous", P(f"Observed | duplicates {t['replay']['duplicates']}, decreases {t['replay']['decreasing']}, max seq {t['replay']['seq_max']}", C)],
                    ["Rekeys / lifetimes", f"{t['rekey_count']} rekey(s)" + (f", intervals {t['lifetimes']} s" if t["lifetimes"] else ""), "Observed"],
                    ["Metadata leak meter", f"{t.get('leak_score')} / 100", P(f"size diversity {t.get('size_diversity')}; TFC padding {'likely' if t.get('tfc_padding_likely') else 'not seen'}", C)],
                    ["ESN / key length / replay window", "Unknown", "never transmitted on the wire"]]
            block.append(table(rows, [W * 0.22, W * 0.36, W * 0.42]))
            if fr.get("candidates"):
                block.append(P("Framing candidates (physics posterior): " + "; ".join(f"{c['label'].split(' (')[0]} = {c['posterior']}" for c in fr["candidates"][:5]), S))
            el.append(KeepTogether(block))
        el.append(P("7. IKE negotiation details", H2))
        for i in f["ike"]:
            if not i.get("complete"):
                continue
            block = [P(f"IKEv{i['version']} {i['initiator']} -> {i['responder']}" + (f" ({i['v1_mode']} mode)" if i.get("v1_mode") else "") +
                       f" | ports {'/'.join(str(p) for p in i['ports'])} | {i['messages']} messages over {i['duration']} s", H3)]
            rows = [["Field", "Value", "Evidence"],
                    ["Encryption", i["encr_label"] + (" (AEAD)" if i.get("encr_aead") else ""), "Observed"],
                    ["PRF / Integrity", f"{i.get('prf')} / {i.get('integ') or ('none (AEAD)' if i.get('encr_aead') else '-')}", "Observed"],
                    ["Key exchange", P(f"{i.get('dh')} ({i.get('dh_bits')}-bit security, RFC 8247: {i.get('dh_status')})" + (f" + <b>{', '.join(i['pqc_groups'])}</b> hybrid" if i.get("pqc_hybrid") else ""), C), "Observed"],
                    ["Authentication", P(f"{i['auth'].get('method') or 'not visible'}" + (f" - {i['auth']['evidence']}" if i['auth'].get('evidence') else "") + (f" - {i['auth']['note']}" if i['auth'].get('note') else ""), C), f"{i['auth'].get('tier')}" + (f" {i['auth']['confidence']}" if i['auth'].get('confidence') else "")],
                    ["Offered proposals", P("<br/>".join(i["offered"]) + (f"<br/><font color='#C62828'>weak: {', '.join(i['weak_offered'])}</font>" if i["weak_offered"] else ""), C), "Observed"],
                    ["Notifications", P(", ".join(i["notifies"]) or "-", C), ""],
                    ["Vendor IDs", P(", ".join(v["vendor"] for v in i["vendor_ids"]) or "-", C), "Observed"],
                    ["Identities (cleartext)", P(", ".join(f"{x['type_name']}: {x['value']}" for x in i["ids"]) or "-", C), "Observed" if i["ids"] else ""],
                    ["Exchanges", P(", ".join(f"{k} x{v}" for k, v in i["exchanges"].items()), C), ""],
                    ["NAT-T", "in use (UDP 4500)" if i["nat_t"] else ("capable, not used" if i.get("natt_capable") else "no"), "Observed"]]
            block.append(table(rows, [W * 0.22, W * 0.58, W * 0.2]))
            el.append(KeepTogether(block))
        el.append(P(f"8. Check catalogue status ({a['checks_total']} checks)", H2))
        rows = [["ID", "Check", "Scope", "Severity", "Status"]]
        for c in a["check_results"]:
            stt = {"fail": f"FAIL ({c['count']})", "info": "INFO", "na": "n/a", "pass": "pass"}[c["status"]]
            rows.append([c["id"], P(c["title"], C), c["scope"], c["severity"], P(f"<font color='{ {'fail': '#C62828', 'info': '#EF6C00', 'na': '#90A4AE', 'pass': '#2E7D32'}[c['status']] }'><b>{stt}</b></font>", C)])
        el.append(table(rows, [W * 0.12, W * 0.5, W * 0.12, W * 0.13, W * 0.13], font=7.2))
        el.append(P("9. Methodology and limits", H2))
        for s_ in ("<b>Parsing.</b> IKEv1/IKEv2 headers and cleartext payloads are decoded byte-exactly; ESP/AH give SPI, sequence number and length. Encrypted payloads are used only through their sizes.",
                   "<b>Length physics.</b> ESP payload length = IV + ceil((P+2)/block)*block + ICV. Residues mod 16/8/4 identify the cipher framing; well-known inner packet sizes (52-byte TCP ACK, 84-byte ping, 200-byte G.711 frame) pin the IV+ICV overhead and the encapsulation mode. Posteriors are Bayesian with mild priors, blended with a RandomForest trained on physically framed synthetic flows (0.6 physics / 0.4 ML).",
                   "<b>Traffic classification.</b> 37 flow features -> calibrated RandomForest over 8 classes. The shipped model is trained on simulated flows; retrain with lab captures before operational use.",
                   "<b>Honest limits.</b> AES-128 vs AES-256, AES-GCM vs ChaCha20-Poly1305 and HMAC-SHA1-96 vs HMAC-MD5-96 share identical framing and cannot be separated passively. ESN, replay window and the IKEv2 authentication method are never visible. PFS needs a rekey inside the capture. Confidence below 0.6 is reported as Unknown.",
                   "<b>Standards.</b> RFC 4301/4302/4303, RFC 7296, RFC 8221, RFC 8247, RFC 9370, RFC 9395, NIST SP 800-77r1, NSA CNSA 2.0, draft-ietf-ipsecme-ikev2-mlkem."):
            el.append(P(s_, N))
    el.append(Spacer(1, 10))
    el.append(P(f"IPsec X-Ray v{result['version']} | SIH 2026 SIH26160 (NTRO) | Team Sudo Spandr | passive analysis only: no keys, no decryption, no injection.", S))
    doc.build(el)
    return buf.getvalue()
