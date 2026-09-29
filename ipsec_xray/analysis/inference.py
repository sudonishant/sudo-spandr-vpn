"""Turn a reconstructed Session into a JSON-serialisable *facts* document with evidence tiers.

Tiers:  Observed  – read directly from cleartext protocol fields
        Inferred  – derived from side-channels (lengths, timing, sizes) with a calibrated confidence
        Unknown   – not recoverable passively (reported explicitly, never guessed silently)
"""
from __future__ import annotations

import math
from collections import Counter

from ..ml.models import Models
from ..ml.simulate import CLASS_LABELS
from ..protocols import registry as R
from .features import cipher_features, traffic_features
from .physics import CAND_BY_KEY, CANDIDATES, analyse_lengths
from .session import Session, pair_flows

PHYS_W, ML_W = 0.6, 0.4
INFER_THRESHOLD = 0.6
WEAK_DH = {1, 2, 5, 22, 23, 24}
MIN_DH = {14}
PQC_GROUPS = {35, 36, 37}


def _strength(family: str | None, bits) -> str:
    """Coarse strength class for an encryption algorithm."""
    if family in ("null",):
        return "none"
    if family == "legacy":
        return "broken" if (bits or 0) <= 64 else "weak"
    if family is None:
        return "unknown"
    return "strong"


def _tier(conf: float, min_conf: float = INFER_THRESHOLD) -> str:
    return "Inferred" if conf >= min_conf else "Unknown"


def _framing_key(c) -> str:
    return f"o{c.overhead}_b{c.block}"


def _chosen_dict(prop) -> dict:
    if prop is None:
        return {}
    d = {"protocol": prop.protocol_name, "summary": prop.summary()}
    for t in prop.transforms:
        if t.ttype == 1:
            d["encr"], d["encr_id"], d["keylen"] = t.name, t.tid, t.keylen
            meta = R.IKEV2_ENCR.get(t.tid)
            d["encr_aead"] = bool(meta[3]) if meta else False
            d["encr_family"] = meta[6] if meta else None
            d["encr_bits"] = (meta[5] if meta and meta[5] is not None else t.keylen) if meta else t.keylen
            d["encr_strength"] = _strength(meta[6], d["encr_bits"]) if meta else "unknown"
            d["encr_status"] = meta[4] if meta else "unknown"
        elif t.ttype == 2:
            d["prf"], d["prf_id"] = t.name, t.tid
        elif t.ttype == 3:
            d["integ"], d["integ_id"] = t.name, t.tid
        elif t.ttype == 4:
            d["dh"], d["dh_id"] = t.name, t.tid
            d["dh_bits"] = R.DH_GROUPS[t.tid][2] if t.tid in R.DH_GROUPS else 0
        elif t.ttype == 5:
            d["esn"] = t.tid == 1
        elif 6 <= t.ttype <= 12:
            d.setdefault("addke", []).append({"type": t.ttype, "id": t.tid, "name": t.name})
    return d


def _weak_offered(props) -> list[str]:
    weak = []
    for p in props:
        for t in p.transforms:
            if t.ttype == 1:
                fam = None
                if t.tid in R.IKEV2_ENCR and not t.name.endswith("_CBC"):
                    fam = R.IKEV2_ENCR[t.tid][6]
                elif t.name.split("_")[0] in ("DES", "3DES", "IDEA", "CAST", "BLOWFISH", "RC5", "NULL"):
                    fam = "legacy" if t.name != "NULL" else "null"
                if fam in ("legacy", "null"):
                    weak.append(t.label())
            elif t.ttype == 2 and (t.name in ("HMAC_MD5", "HMAC_SHA1", "HMAC_TIGER") or (t.tid in R.IKEV2_PRF and R.IKEV2_PRF[t.tid][2] <= 80 and not t.name.startswith("HMAC_SHA2"))):
                weak.append(t.name)
            elif t.ttype == 3 and t.tid in R.IKEV2_INTEG and R.IKEV2_INTEG[t.tid][3] <= 80:
                weak.append(t.name)
            elif t.ttype == 4 and t.tid in WEAK_DH:
                weak.append(t.name)
    return sorted(set(weak))


def _v1_auth(sa) -> dict:
    a = sa.v1_attrs.get("AUTH")
    if not a:
        return {"method": None, "tier": "Unknown"}
    return {"method": a, "tier": "Observed", "psk": ("PSK" in a or "PRE_SHARED" in a), "xauth": "XAUTH" in a, "rsa_encryption": "RSA_ENCRYPTION" in a}


def _v2_auth_guess(sa) -> dict:
    """IKE_AUTH is encrypted; the number of rounds and the message sizes still hint at the method."""
    rounds = sum(1 for e in sa.exchanges if e.exchange == "IKE_AUTH" and not e.response)
    lens = [e.length for e in sa.exchanges if e.exchange == "IKE_AUTH"]
    if not lens:
        return {"method": None, "tier": "Unknown", "note": "no IKE_AUTH captured"}
    if rounds >= 3:
        return {"method": "EAP (multi-round)", "tier": "Inferred", "confidence": 0.75, "psk": False, "eap": True,
                "evidence": f"{rounds} IKE_AUTH round trips - EAP conversation"}
    if max(lens) >= 900:
        return {"method": "certificate / digital signature (likely)", "tier": "Inferred", "confidence": 0.6, "psk": False,
                "evidence": f"IKE_AUTH up to {max(lens)} B - large enough for CERT + signature"}
    if max(lens) <= 420:
        return {"method": "PSK (likely)", "tier": "Inferred", "confidence": 0.6, "psk": True,
                "evidence": f"single IKE_AUTH round, at most {max(lens)} B - too small for a certificate"}
    return {"method": None, "tier": "Unknown", "note": "IKE_AUTH payload is encrypted; size is in an ambiguous band"}


def _pfs_from_sa(sa, tunnel_rekeys: list) -> dict:
    """Infer PFS from the size of encrypted CREATE_CHILD_SA / Quick-Mode requests."""
    evs = [r for r in sa.child_rekeys if r.get("req_len")]
    if not evs:
        return {"state": "unknown", "tier": "Unknown", "confidence": 0.0,
                "evidence": "no Child-SA rekey inside the capture window; capture across a rekey (strongSwan default 1 h) to determine PFS"}
    lens = [r["req_len"] for r in evs]
    big = [l for l in lens if l >= 300]
    small = [l for l in lens if l < 260]
    kind = "Quick Mode" if sa.version == 1 else "CREATE_CHILD_SA"
    if big and not small:
        L = max(lens)
        base = 230 if sa.version == 2 else 200       # typical request without KE (proposal list + TS + nonce)
        ke = L - base
        # size classes: large MODP / ML-KEM sizes are distinctive, small ECDH groups are not separable from proposal-list length
        if ke >= 1450:
            guess, gstat = "ML-KEM-1024 (+ classical) hybrid", "PQC"
        elif ke >= 1050:
            guess, gstat = "ML-KEM-768 (+ classical) hybrid", "PQC"
        elif ke >= 700:
            guess, gstat = "ML-KEM-512 hybrid or MODP-6144/8192", "PQC/strong"
        elif ke >= 470:
            guess, gstat = "MODP-4096 (or larger)", "strong"
        elif ke >= 340:
            guess, gstat = "MODP-3072", "strong"
        elif ke >= 215:
            guess, gstat = "MODP-2048 class (or ECP-521 + long proposal list)", "acceptable"
        else:
            guess, gstat = "ECDH class (ECP-256/384, X25519) or MODP-1024/1536 - too small to separate", "ambiguous"
        conf = 0.9 if L >= 400 else 0.75
        return {"state": "on", "tier": "Inferred", "confidence": conf, "evidence": f"{kind} request {L} B is large enough to carry a KE payload (~{ke} B of key-exchange data)",
                "group_guess": guess, "group_guess_status": gstat, "ke_bytes_estimate": ke, "rekeys": len(evs)}
    if small and not big:
        return {"state": "off", "tier": "Inferred", "confidence": 0.85, "rekeys": len(evs),
                "evidence": f"{kind} request only {max(lens)} B: no room for a KE payload (no PFS)"}
    return {"state": "mixed", "tier": "Inferred", "confidence": 0.5, "rekeys": len(evs), "evidence": f"{kind} request sizes {sorted(set(lens))} B are in the ambiguous 260-300 B band"}


def _ike_facts(sa) -> dict:
    chosen = _chosen_dict(sa.chosen)
    offered = [p.summary() for p in sa.offered]
    weak_off = _weak_offered(sa.offered)
    dh_id = chosen.get("dh_id", sa.ke_group)
    dh_meta = R.DH_GROUPS.get(dh_id) if dh_id is not None else None
    pqc = [g for g, _ in sa.add_ke if g in PQC_GROUPS] or [a["id"] for a in chosen.get("addke", []) if a["id"] in PQC_GROUPS] or \
          ([dh_id] if dh_id in PQC_GROUPS else [])
    if sa.version == 1:
        auth = _v1_auth(sa)
        encr = sa.v1_attrs.get("ENCR")
        keylen = sa.v1_attrs.get("KEY_LENGTH")
        hashalg = sa.v1_attrs.get("HASH")
        fam, bits = None, None
        for _, (nm, b, f) in R.IKEV1_ENCR.items():
            if nm == encr:
                fam, bits = f, (b if b is not None else keylen)
        chosen = dict(chosen, encr=encr, keylen=keylen, prf=f"HMAC_{hashalg}" if hashalg else None, integ=f"HMAC_{hashalg}" if hashalg else None,
                      dh=R.dh_name(dh_id) if dh_id is not None else None, dh_id=dh_id, encr_strength=_strength(fam, bits), encr_family=fam,
                      encr_bits=bits, encr_aead=False, lifetime=sa.v1_attrs.get("LIFE_DURATION"), lifetime_type=sa.v1_attrs.get("LIFE_TYPE"),
                      hash=hashalg)
    else:
        auth = _v2_auth_guess(sa)
    exch_counts = Counter(e.exchange for e in sa.exchanges)
    init_count = sum(1 for e in sa.exchanges if e.exchange == "IKE_SA_INIT" and not e.response)
    auth_count = sum(1 for e in sa.exchanges if e.exchange == "IKE_AUTH")
    complete = (auth_count > 0) if sa.version == 2 else any(e.exchange == "QUICK_MODE" or e.encrypted_len for e in sa.exchanges)
    return {
        "complete": complete,
        "version": sa.version, "spi_i": sa.spi_i, "spi_r": sa.spi_r, "initiator": sa.initiator, "responder": sa.responder,
        "ipver": sa.ipver, "ports": sorted(p for p in sa.ports if p), "nat_t": sa.nat_t, "natt_capable": sa.natt_capable, "v1_mode": sa.v1_mode,
        "duration": round(sa.duration, 3), "messages": len(sa.exchanges), "exchanges": dict(exch_counts),
        "exchange_log": [{"ts": round(e.ts, 6), "exchange": e.exchange, "dir": e.direction, "len": e.length, "msg_id": e.msg_id,
                          "response": e.response, "encrypted_len": e.encrypted_len, "payloads": e.payloads, "notifies": e.notifies}
                         for e in sa.exchanges[:400]],
        "offered": offered, "offered_count": sum(max(1, len(p.v1_transforms)) for p in sa.offered), "weak_offered": weak_off, "chosen": chosen,
        "encr": chosen.get("encr"), "keylen": chosen.get("keylen"), "prf": chosen.get("prf"), "integ": chosen.get("integ"),
        "dh": chosen.get("dh") or (R.dh_name(dh_id) if dh_id is not None else None), "dh_id": dh_id,
        "dh_bits": dh_meta[2] if dh_meta else 0, "dh_status": dh_meta[1] if dh_meta else "unknown", "dh_kind": dh_meta[4] if dh_meta else None,
        "encr_strength": chosen.get("encr_strength", "unknown"), "encr_aead": chosen.get("encr_aead", False),
        "ke_len": sa.ke_len, "add_ke": [{"group": g, "name": R.dh_name(g), "len": l} for g, l in sa.add_ke],
        "pqc_hybrid": bool(pqc), "pqc_groups": [R.dh_name(g) for g in pqc],
        "notifies": sorted(sa.notifies), "vendor_ids": [{"hex": h[:32], "vendor": v} for h, v in sa.vendor_ids],
        "ids": sa.ids, "id_plaintext": bool(sa.ids), "auth": auth,
        "cookie_challenge": "COOKIE" in sa.notifies, "fragmentation": "IKEV2_FRAGMENTATION_SUPPORTED" in sa.notifies,
        "mobike": "MOBIKE_SUPPORTED" in sa.notifies, "redirect": "REDIRECT_SUPPORTED" in sa.notifies,
        "sig_hash_algs": sorted(sa.sig_hash_algs), "sig_hash_sha1": 1 in sa.sig_hash_algs, "intermediate": sa.intermediate,
        "nonstandard_ports": any(p not in (500, 4500) for p in sa.ports if p),
        "vendor_legacy": any(("Unity" in v) or ("draft" in v) or ("Check Point" in v) for _, v in sa.vendor_ids),
        "errors": sa.errors, "parse_errors": sa.parse_errors, "child_rekeys": sa.child_rekeys, "child_rekey_count": len(sa.child_rekeys),
        "ike_auth_lens": sa.ike_auth_lens, "init_requests": init_count, "auth_exchanges": auth_count,
        "cert_seen": sa.cert_seen, "certreq_seen": sa.certreq_seen, "hash_or_sig_plain": sa.hash_or_sig_plain,
        "nonce_lens": sorted(set(sa.nonce_lens)), "informational": sa.informational, "deletes": sa.deletes,
        "lifetime_seconds": chosen.get("lifetime") if chosen.get("lifetime_type", "seconds") == "seconds" else None,
        "encr_label": (f"{chosen.get('encr')}-{chosen.get('keylen')}" if chosen.get("keylen") else chosen.get("encr")) or "unknown",
    }


_PORT_CLASS = [
    (17, {5060, 5061}, "voip"), (17, range(16384, 32768), "voip"), (6, {5060, 5061}, "voip"),
    (6, {80, 443, 8080, 8443}, "web"), (17, {443}, "video"), (6, {1935, 554}, "video"), (17, {554, 5004}, "video"),
    (6, {25, 110, 143, 465, 587, 993, 995}, "email"), (6, {22}, "ssh"), (6, {5222, 5223, 5228}, "chat"),
    (6, {20, 21, 445, 139, 873}, "file"),
]


def _ah_traffic(inner: Counter) -> dict:
    """AH payload is cleartext: classify from the inner protocol/ports (Observed tier)."""
    if not inner:
        return {"label": "not classified (AH, no inner packets)", "class": None, "confidence": 0.0, "tier": "Unknown", "top": []}
    total = sum(inner.values())
    classes = Counter()
    for (proto, port), cnt in inner.items():
        cls = None
        if proto in (1, 58):
            cls = "icmp"
        else:
            for p, ports, c in _PORT_CLASS:
                if proto == p and port in ports:
                    cls = c
                    break
        classes[cls or f"other ({'tcp' if proto == 6 else 'udp' if proto == 17 else 'proto ' + str(proto)}/{port})"] += cnt
    top = [{"class": k, "label": CLASS_LABELS.get(k, k), "p": round(v / total, 3)} for k, v in classes.most_common(3)]
    best = top[0]
    return {"label": f"{best['label']} (cleartext ports)", "class": best["class"] if best["class"] in CLASS_LABELS else None,
            "confidence": 1.0, "tier": "Observed", "top": top}


def _tunnel_facts(t: dict, models: Models, ike_lookup: dict) -> dict:
    flows = t["flows"]
    a, b = t["peers"]
    # merge both directions with direction labels relative to the IKE initiator when known
    sa = ike_lookup.get(frozenset((a, b)))
    init = sa["initiator"] if sa else flows[0].src
    merged = []
    for f in flows:
        d = "up" if f.src == init else "down"
        merged.extend((ts, d, ln) for ts, ln, _ in f.pkts)
    merged.sort(key=lambda e: e[0])
    lens = [e[2] for e in merged]
    n = len(lens)
    protocol = t["protocol"]
    out = {"peers": [a, b], "protocol": protocol, "udp_encap": t["udp_encap"], "ipver": t["ipver"], "packets": n,
           "bytes": sum(lens), "duration": round(merged[-1][0] - merged[0][0], 3) if n > 1 else 0.0,
           "flows": [], "rekeys": t["rekeys"], "rekey_count": len(t["rekeys"]),
           "lifetimes": [round(x, 1) for x in t["lifetimes"]], "ike_ref": sa["spi_i"] if sa else None,
           "ike_version": sa["version"] if sa else None}
    seq_dups = seq_dec = seq_gaps = 0
    seq_max = 0
    for f in flows:
        st = f.seq_stats()
        seq_dups += st["duplicates"]
        seq_dec += st["reorders"]
        seq_gaps += st["gaps"]
        seq_max = max(seq_max, st["max"])
        ls = f.lengths()
        out["flows"].append({"src": f.src, "dst": f.dst, "spi": f"0x{f.spi:08x}", "packets": f.count, "bytes": f.bytes,
                             "first_ts": round(f.first_ts, 6), "last_ts": round(f.last_ts, 6), "seq": st,
                             "len_min": min(ls) if ls else 0, "len_max": max(ls) if ls else 0,
                             "len_hist": dict(Counter(ls).most_common(12)), "icv_len": f.icv_len})
    out["replay"] = {"tier": "Observed", "duplicates": seq_dups, "decreasing": seq_dec, "gaps": seq_gaps, "seq_max": seq_max,
                     "monotonic": seq_dups == 0 and seq_dec == 0}
    out["max_flow_bytes"] = max((f.bytes for f in flows), default=0)
    out["frac_mtu_size"] = round(sum(1 for l in lens if l >= 1450) / n, 4) if n else 0.0
    out["ike_encr_aead"] = sa["encr_aead"] if sa else None
    out["ike_dh_id"] = sa["dh_id"] if sa else None
    out["ike_dh_bits"] = sa["dh_bits"] if sa else None
    out["ike_hash"] = (sa["chosen"].get("hash") if sa else None)
    out["ike_vendor_legacy"] = sa["vendor_legacy"] if sa else False
    # ---------------- cipher framing
    if protocol == "AH":
        icv = flows[0].icv_len or 0
        integ = {12: "HMAC-SHA1-96 / HMAC-MD5-96 / AES-XCBC-96", 16: "HMAC-SHA2-256-128 / AES-GMAC-128", 24: "HMAC-SHA2-384-192",
                 32: "HMAC-SHA2-512-256"}.get(icv, f"{icv}-byte ICV")
        out["framing"] = {"label": f"AH (no encryption), ICV {icv} B = {integ}", "family": "ah", "confidence": 1.0, "tier": "Observed",
                          "overhead": icv, "block": 4, "integ_bits": icv * 8, "aead": False, "null_encr": True, "legacy": False,
                          "candidates": [], "framing_groups": [], "physics": {}, "ml": {}}
        nh = flows[0].ah_next_header
        mode = "tunnel" if nh in (4, 41) else "transport"
        out["mode"] = {"value": mode, "best_guess": mode, "confidence": 1.0, "tier": "Observed",
                       "physics": {}, "ml": {}, "evidence": f"AH next-header {nh} read from the packet"}
        inner = Counter()
        for f in flows:
            inner.update(f.ah_inner)
        out["traffic"] = _ah_traffic(inner)
        out["ah_next_header"] = nh
        out["size_diversity"] = 0.0
        return out
    phys = analyse_lengths(lens)
    ml_c = models.predict_cipher(cipher_features(lens)) if models.available and n >= 3 else {}
    ent = {"n": 0, "mean_entropy": None, "ip_header_like": 0.0}
    ents = [f.entropy_summary() for f in flows if f.entropy_summary()["n"]]
    if ents:
        tot = sum(e["n"] for e in ents)
        ent = {"n": tot, "mean_entropy": round(sum(e["mean_entropy"] * e["n"] for e in ents) / tot, 3),
               "ip_header_like": round(sum(e["ip_header_like"] * e["n"] for e in ents) / tot, 3)}
    plaintext_visible = ent["n"] >= 5 and ent["mean_entropy"] is not None and ent["mean_entropy"] < 0.85 and ent["ip_header_like"] > 0.8
    random_looking = ent["n"] >= 5 and ent["mean_entropy"] is not None and ent["mean_entropy"] >= 0.9
    # combine over framing groups
    comb = {}
    for g in phys["framing_groups"]:
        key = f"o{g['overhead']}_b{g['block']}"
        p_phys = max(g["posterior"], 1e-4)
        p_ml = max(ml_c.get(key, 1.0 / max(len(ml_c), 1)), 1e-4) if ml_c else 1.0
        comb[key] = (p_phys ** PHYS_W) * (p_ml ** ML_W)
    # entropy evidence: NULL encryption shows the inner IP header; real ciphertext is random
    for k in list(comb):
        is_null = any(CAND_BY_KEY[m].family == "null" for g in phys["framing_groups"] if f"o{g['overhead']}_b{g['block']}" == k for m in g["members"])
        if plaintext_visible:
            comb[k] *= 40.0 if is_null else 1.0
        elif random_looking:
            comb[k] *= 0.05 if is_null else 1.0
    z = sum(comb.values()) or 1.0
    comb = {k: v / z for k, v in comb.items()}
    best = max(comb, key=comb.get)
    conf = comb[best]
    if n < 10:
        conf *= 0.6
    grp = next(g for g in phys["framing_groups"] if f"o{g['overhead']}_b{g['block']}" == best)
    members = [CAND_BY_KEY[k] for k in grp["members"]]
    lead = members[0]
    label = " | ".join(m.label for m in members) if len(members) > 1 else lead.label
    fam = lead.family
    out["framing"] = {
        "label": label, "lead_key": lead.key, "family": fam, "confidence": round(conf, 3), "tier": _tier(conf),
        "overhead": lead.overhead, "block": lead.block, "iv": lead.iv, "icv": lead.icv, "integ_bits": lead.integ_bits,
        "aead": fam == "aead", "null_encr": fam == "null", "legacy": fam == "legacy", "cbc": fam == "cbc",
        "members": [m for c in members for m in c.members],
        "candidates": phys["candidates"][:6], "framing_groups": phys["framing_groups"][:5],
        "physics": {"top": phys["top"], "confidence": phys["confidence"], "distinct": phys["distinct"], "min_lp": phys["min_lp"],
                    "residues_mod16": phys["residues_mod16"]},
        "ml": {k: round(v, 3) for k, v in sorted(ml_c.items(), key=lambda kv: -kv[1])[:4]},
        "combined": {k: round(v, 3) for k, v in sorted(comb.items(), key=lambda kv: -kv[1])[:4]},
        "entropy": ent, "plaintext_visible": plaintext_visible,
        "note": "AES-128 vs AES-256 and AES-GCM vs ChaCha20 are indistinguishable on the wire; the label lists every algorithm with this framing.",
    }
    if plaintext_visible:
        out["framing"]["tier"] = "Observed"
        out["framing"]["note"] = "Inner IP header is readable in the ESP payload (NULL encryption): confidentiality is absent."
    # ---------------- mode
    m_phys = {phys["mode"]: phys["mode_confidence"], ("transport" if phys["mode"] == "tunnel" else "tunnel"): 1 - phys["mode_confidence"]}
    ml_m = {}
    if models.available and n >= 3:
        from ..ml.train import mode_features
        ml_m = models.predict_mode(mode_features(lens))
    mode_comb = {}
    for m in ("tunnel", "transport"):
        mode_comb[m] = (max(m_phys.get(m, 0.5), 1e-4) ** PHYS_W) * (max(ml_m.get(m, 0.5), 1e-4) ** ML_W)
    zz = sum(mode_comb.values())
    mode_comb = {k: v / zz for k, v in mode_comb.items()}
    bm = max(mode_comb, key=mode_comb.get)
    out["mode"] = {"value": bm if mode_comb[bm] >= INFER_THRESHOLD else "unknown", "best_guess": bm, "confidence": round(mode_comb[bm], 3),
                   "tier": _tier(mode_comb[bm]), "physics": {k: round(v, 3) for k, v in m_phys.items()}, "ml": {k: round(v, 3) for k, v in ml_m.items()}}
    # ---------------- cleartext inner packets (ESP with ENCR_NULL): mode and application are Observed, not inferred
    null_inner, null_mode = Counter(), Counter()
    for f in flows:
        null_inner.update(f.null_inner)
        null_mode.update(f.null_mode)
    null_seen = sum(null_inner.values())
    if null_seen >= 5 and null_seen >= 0.5 * min(n, 256) and lead.family == "null":
        m_obs = null_mode.most_common(1)[0][0]
        out["mode"] = {"value": m_obs, "best_guess": m_obs, "confidence": 1.0, "tier": "Observed", "physics": out["mode"].get("physics", {}),
                       "ml": out["mode"].get("ml", {}), "evidence": f"ESP trailer decoded in {null_seen} NULL-encrypted packets (next-header + padding pattern)"}
        out["traffic"] = _ah_traffic(null_inner)
        out["traffic"]["label"] = out["traffic"]["label"].replace("(cleartext ports)", "(inner packet visible - NULL encryption)")
        out["cleartext_inner"] = {"packets": null_seen, "top": out["traffic"]["top"]}
        out["plaintext_visible"] = True
    cleartext_done = "cleartext_inner" in out
    # ---------------- traffic class
    if cleartext_done:
        pass
    elif models.available and n >= 5:
        probs = models.predict_traffic(traffic_features(merged))
        ranked = sorted(probs.items(), key=lambda kv: -kv[1])
        top_cls, top_p = ranked[0]
        # short flows are less reliable
        if n < 30:
            top_p *= 0.8
        out["traffic"] = {"label": CLASS_LABELS.get(top_cls, top_cls), "class": top_cls, "confidence": round(top_p, 3), "tier": _tier(top_p),
                          "top": [{"class": c, "label": CLASS_LABELS.get(c, c), "p": round(p, 3)} for c, p in ranked[:3]]}
    else:
        out["traffic"] = {"label": "insufficient packets", "class": None, "confidence": 0.0, "tier": "Unknown", "top": []}
    # metadata leak meter 0..100: how identifiable the application is + size diversity (no TFC padding)
    distinct_ratio = len(set(lens)) / n if n else 0
    leak = 100 * out["traffic"]["confidence"] * (0.6 + 0.4 * min(1.0, distinct_ratio * 5))
    out["leak_score"] = round(leak, 1)
    out["size_diversity"] = round(distinct_ratio, 4)
    out["tfc_padding_likely"] = bool(n >= 20 and (Counter(lens).most_common(1)[0][1] / n) > 0.95 and max(lens) >= 1400)
    return out


def build_facts(sess: Session, path_name: str = "") -> dict:
    models = Models.get()
    ike_all = [_ike_facts(sa) for sa in sess.ike_sas.values()]
    ike = [i for i in ike_all if i["complete"]]
    incomplete = [i for i in ike_all if not i["complete"]]
    ike_lookup = {frozenset((i["initiator"], i["responder"])): i for i in ike}
    for i in ike_all:
        ike_lookup.setdefault(frozenset((i["initiator"], i["responder"])), i)
    tunnels = []
    for t in pair_flows(sess):
        tf = _tunnel_facts(t, models, ike_lookup)
        sa = ike_lookup.get(frozenset(t["peers"]))
        pfs = _pfs_from_sa(sess.ike_sas[sa["spi_i"]], t["rekeys"]) if sa else {"state": "unknown", "tier": "Unknown", "confidence": 0.0,
                                                                                  "evidence": "no IKE SA captured for this tunnel"}
        tf["pfs"] = pfs
        tunnels.append(tf)
    for i in ike:
        i["pfs"] = _pfs_from_sa(sess.ike_sas[i["spi_i"]], [])
    # config drift: same peer pair, different IKE proposals
    drift = []
    by_pair = {}
    for i in ike:
        by_pair.setdefault(frozenset((i["initiator"], i["responder"])), []).append(i["chosen"].get("summary"))
    for pair, sums in by_pair.items():
        if len(set(s for s in sums if s)) > 1:
            drift.append(sorted(pair))
    spi_map = {}
    for t in tunnels:
        for f in t["flows"]:
            spi_map.setdefault(f["spi"], set()).add(tuple(t["peers"]))
    spi_reuse = [s for s, peers in spi_map.items() if len(peers) > 1]
    incomplete_sources = sorted(set(i["initiator"] for i in incomplete))
    facts = {
        "file": path_name,
        "capture": {"packets": sess.packets_total, "duration": round(sess.duration, 3), "ike_messages": sess.ike_messages,
                    "incomplete_sas": len(incomplete), "incomplete_sources": len(incomplete_sources),
                    "incomplete_examples": [{"initiator": i["initiator"], "responder": i["responder"], "exchanges": i["exchanges"],
                                             "cookie": "COOKIE" in i["notifies"]} for i in incomplete[:5]],
                    "esp_flows": len(sess.esp_flows), "ah_flows": len(sess.ah_flows), "ipv4": 4 in sess.ipvers, "ipv6": 6 in sess.ipvers,
                    "fragments": sess.fragments, "non_ipsec_packets": sess.non_ipsec_packets, "endpoints": sorted(sess.endpoints),
                    "cleartext_between_peers": dict(sess.cleartext), "ike_sa_count": len(ike), "tunnel_count": len(tunnels),
                    "config_drift_pairs": drift, "spi_reuse": spi_reuse,
                    "ike_init_rate_per_min": round(60 * sum(i["init_requests"] for i in ike_all) / max(sess.duration, 1), 2),
                    "orphan_inits": sum(1 for i in ike_all if i["version"] == 2 and i["auth_exchanges"] == 0 and i["init_requests"] > 0),
                    "cookie_seen": any("COOKIE" in i["notifies"] for i in ike_all), "complete_sas": len(ike),
                    "esp_over_tcp": sess.tcp_4500_packets > 0, "tcp_4500_packets": sess.tcp_4500_packets,
                    "parse_errors": sum(i["parse_errors"] for i in ike_all),
                    "models_available": models.available, "model_meta": models.meta.get("models", {})},
        "ike": ike + incomplete[:3], "tunnels": tunnels,
    }
    facts["summary"] = _summary(facts)
    return facts


def _summary(f: dict) -> dict:
    ike = [i for i in f["ike"] if i.get("complete")]
    tun = f["tunnels"]
    obs = inf = unk = 0
    for i in ike:
        obs += 6 if i["version"] == 1 else 4          # encr/prf/integ/dh (+auth,lifetime for v1)
        unk += 0 if i["version"] == 1 else 2          # auth method, child proposal
        if i["pfs"]["tier"] == "Inferred":
            inf += 1
        elif i["pfs"]["tier"] == "Unknown":
            unk += 1
    for t in tun:
        for k in ("framing", "mode", "traffic"):
            tier = t[k]["tier"]
            obs += tier == "Observed"
            inf += tier == "Inferred"
            unk += tier == "Unknown"
        obs += 1  # replay
        unk += 2  # ESN, key length
    total = max(obs + inf + unk, 1)
    conf_vals = [t["framing"]["confidence"] for t in tun] + [t["mode"]["confidence"] for t in tun] + [t["traffic"]["confidence"] for t in tun]
    conf_vals += [i["pfs"]["confidence"] for i in ike if i["pfs"]["tier"] != "Unknown"]
    return {"tiers": {"observed": obs, "inferred": inf, "unknown": unk, "observed_pct": round(100 * obs / total), "inferred_pct": round(100 * inf / total),
                      "unknown_pct": round(100 * unk / total)},
            "ai_confidence": round(100 * (sum(conf_vals) / len(conf_vals)), 1) if conf_vals else 0.0,
            "ike_versions": sorted(set(i["version"] for i in ike)),
            "primary_ike": ike[0]["encr_label"] + (f" / {ike[0]['integ']}" if ike[0].get("integ") and not ike[0].get("encr_aead") else "") +
                           (f" / {ike[0]['dh']}" if ike[0].get("dh") else "") if ike else "no IKE seen",
            "primary_esp": tun[0]["framing"]["label"] if tun else "no ESP seen",
            "primary_traffic": tun[0]["traffic"]["label"] if tun else "-",
            "primary_mode": tun[0]["mode"]["value"] if tun else "-",
            "pfs": ike[0]["pfs"]["state"] if ike else "unknown"}
