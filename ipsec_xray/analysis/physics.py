"""ESP packet-length physics.

For every ESP packet the on-wire payload length (after SPI+Seq) is
    Lp = IV + C + ICV,     C = P + PadLen + 2,   C ≡ 0 (mod block)
where P is the plaintext (inner packet) length, `block` is 16 for AES/Camellia-CBC, 8 for DES/3DES-CBC and 4 for
counter-mode / AEAD / NULL (RFC 4303 requires 4-byte alignment).  The residues of the observed lengths therefore
reveal the cipher framing, and well-known inner packet sizes ("anchors", e.g. a 52-byte TCP ACK or an 84-byte ping)
reveal the IV+ICV overhead and the encapsulation mode.  This module turns those facts into calibrated posteriors.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass

from ..protocols.registry import ANCHORS


@dataclass(frozen=True)
class Candidate:
    key: str
    label: str
    iv: int
    icv: int
    block: int
    family: str          # cbc / legacy / aead / ctr / null
    integ_bits: int
    prior: float
    members: tuple        # algorithm names sharing this framing

    @property
    def overhead(self) -> int:
        return self.iv + self.icv


CANDIDATES: list[Candidate] = [
    Candidate("aes_cbc_sha1", "AES/Camellia-CBC + HMAC-SHA1-96 (or MD5-96)", 16, 12, 16, "cbc", 96, 0.15,
              ("AES_CBC+HMAC_SHA1_96", "AES_CBC+HMAC_MD5_96", "CAMELLIA_CBC+HMAC_SHA1_96")),
    Candidate("aes_cbc_sha256", "AES/Camellia-CBC + HMAC-SHA2-256-128", 16, 16, 16, "cbc", 128, 0.20,
              ("AES_CBC+HMAC_SHA2_256_128", "CAMELLIA_CBC+HMAC_SHA2_256_128", "AES_CBC+AES_GMAC")),
    Candidate("aes_cbc_sha384", "AES-CBC + HMAC-SHA2-384-192", 16, 24, 16, "cbc", 192, 0.04, ("AES_CBC+HMAC_SHA2_384_192",)),
    Candidate("aes_cbc_sha512", "AES-CBC + HMAC-SHA2-512-256", 16, 32, 16, "cbc", 256, 0.03, ("AES_CBC+HMAC_SHA2_512_256",)),
    Candidate("des3_sha1", "3DES/DES-CBC + HMAC-SHA1-96 (or MD5-96)", 8, 12, 8, "legacy", 96, 0.08,
              ("3DES+HMAC_SHA1_96", "3DES+HMAC_MD5_96", "DES+HMAC_SHA1_96", "DES+HMAC_MD5_96")),
    Candidate("des3_sha256", "3DES-CBC + HMAC-SHA2-256-128", 8, 16, 8, "legacy", 128, 0.03, ("3DES+HMAC_SHA2_256_128",)),
    Candidate("aead_16", "AEAD: AES-GCM-16 / ChaCha20-Poly1305 / AES-CCM-16 (or AES-CTR + SHA2-256)", 8, 16, 4, "aead", 128, 0.28,
              ("AES_GCM_16", "CHACHA20_POLY1305", "AES_CCM_16", "AES_CTR+HMAC_SHA2_256_128")),
    Candidate("aead_12", "AES-GCM-12 / AES-CCM-12 (or AES-CTR + SHA1-96)", 8, 12, 4, "aead", 96, 0.05,
              ("AES_GCM_12", "AES_CCM_12", "AES_CTR+HMAC_SHA1_96")),
    Candidate("aead_8", "AES-GCM-8 / AES-CCM-8", 8, 8, 4, "aead", 64, 0.03, ("AES_GCM_8", "AES_CCM_8")),
    Candidate("null_sha1", "NULL encryption + HMAC-SHA1-96 / MD5-96", 0, 12, 4, "null", 96, 0.05, ("NULL+HMAC_SHA1_96", "NULL+HMAC_MD5_96")),
    Candidate("null_sha256", "NULL encryption + HMAC-SHA2-256-128", 0, 16, 4, "null", 128, 0.06, ("NULL+HMAC_SHA2_256_128",)),
]
CAND_BY_KEY = {c.key: c for c in CANDIDATES}

EPS = 0.02          # likelihood of a length that does not fit a candidate (TFC padding, fragments, odd stacks)
ANCHOR_ALPHA = 1.6  # log-likelihood gain per (weighted) anchor hit
MIN_INNER = {"tunnel": 28, "transport": 8}   # smallest plausible plaintext (IPv4+ICMP hdr / ICMP hdr)


def payload_lengths(total_lengths: list[int]) -> list[int]:
    """ESP total (SPI+Seq+payload) -> payload length Lp."""
    return [t - 8 for t in total_lengths if t > 8]


def fits(lp: int, c: Candidate) -> bool:
    x = lp - c.overhead
    return x >= 2 and x % c.block == 0


def inner_interval(lp: int, c: Candidate) -> tuple[int, int]:
    """Possible plaintext lengths P for a given Lp under candidate c (padding 0..block-1)."""
    c_len = lp - c.overhead
    hi = c_len - 2
    lo = hi - (c.block - 1)
    return max(lo, 0), hi


def _anchor_hits(top: list[tuple[int, float]], c: Candidate, mode: str) -> float:
    score = 0.0
    anchors = ANCHORS[mode]
    for lp, w in top:
        lo, hi = inner_interval(lp, c)
        if any(lo <= a <= hi for a in anchors):
            score += w
    return score


def analyse_lengths(total_lengths: list[int]) -> dict:
    """Return posteriors over cipher framing and mode plus the raw evidence used."""
    lps = payload_lengths(total_lengths)
    n = len(lps)
    out = {"n": n, "distinct": 0, "candidates": [], "top": None, "confidence": 0.0, "mode": None, "mode_confidence": 0.0,
           "framing_groups": [], "min_lp": None, "residues_mod16": {}, "anchors": {}}
    if n == 0:
        return out
    cnt = Counter(lps)
    distinct = list(cnt.items())
    out["distinct"] = len(distinct)
    out["min_lp"] = min(lps)
    out["residues_mod16"] = {str(k): v for k, v in sorted(Counter(lp % 16 for lp in lps).items())}
    # frequency-weighted top lengths for anchor evidence (small packets carry the most information)
    top = sorted(distinct, key=lambda kv: -kv[1])[:8]
    tot = sum(w for _, w in top)
    top_w = [(lp, w / tot) for lp, w in top]

    logs = {}
    anchor_tab = {}
    for c in CANDIDATES:
        ll = math.log(c.prior)
        for lp, cnt_l in distinct:
            if fits(lp, c):
                ll += math.log(c.block / 4.0) * min(3.0, 1 + math.log10(cnt_l))   # restrictive framings earn evidence
            else:
                ll += math.log(EPS) * min(3.0, 1 + math.log10(cnt_l))
        # smallest packet must still contain a plausible inner packet
        lo, hi = inner_interval(min(lps), c)
        mode_ll = {}
        for mode in ("tunnel", "transport"):
            hits = _anchor_hits(top_w, c, mode)
            m_ll = ANCHOR_ALPHA * hits * 3.0
            if hi < MIN_INNER[mode]:
                m_ll += math.log(EPS)
            mode_ll[mode] = m_ll
        anchor_tab[c.key] = mode_ll
        ll += math.log(sum(math.exp(v) for v in mode_ll.values()) / 2.0)
        logs[c.key] = ll
    mx = max(logs.values())
    post = {k: math.exp(v - mx) for k, v in logs.items()}
    z = sum(post.values())
    post = {k: v / z for k, v in post.items()}
    ranked = sorted(post.items(), key=lambda kv: -kv[1])
    out["candidates"] = [{"key": k, "label": CAND_BY_KEY[k].label, "posterior": round(p, 4), "family": CAND_BY_KEY[k].family,
                          "overhead": CAND_BY_KEY[k].overhead, "block": CAND_BY_KEY[k].block,
                          "fit": round(sum(cn for lp, cn in distinct if fits(lp, CAND_BY_KEY[k])) / n, 4)}
                         for k, p in ranked]
    # framing groups: candidates with identical (overhead, block) are indistinguishable by length physics
    groups: dict = {}
    for k, p in post.items():
        c = CAND_BY_KEY[k]
        groups.setdefault((c.overhead, c.block), []).append((k, p))
    fg = []
    for (o, b), members in groups.items():
        fg.append({"overhead": o, "block": b, "posterior": round(sum(p for _, p in members), 4),
                   "members": [k for k, _ in sorted(members, key=lambda kv: -kv[1])]})
    fg.sort(key=lambda g: -g["posterior"])
    out["framing_groups"] = fg
    best_key, best_p = ranked[0]
    out["top"] = best_key
    out["confidence"] = round(fg[0]["posterior"], 4)
    # mode posterior marginalised over candidates
    mode_post = {"tunnel": 0.0, "transport": 0.0}
    for k, p in post.items():
        mll = anchor_tab[k]
        m = max(mll.values())
        ws = {mode: math.exp(v - m) for mode, v in mll.items()}
        zz = sum(ws.values())
        for mode in mode_post:
            mode_post[mode] += p * ws[mode] / zz
    zm = sum(mode_post.values()) or 1.0
    mode_post = {k: v / zm for k, v in mode_post.items()}
    bm = max(mode_post, key=mode_post.get)
    out["mode"] = bm
    out["mode_confidence"] = round(mode_post[bm], 4)
    out["anchors"] = {k: {m: round(v, 3) for m, v in d.items()} for k, d in anchor_tab.items() if k in (best_key, ranked[1][0])}
    return out


def esp_length_for(inner_len: int, c: Candidate, tfc_pad: int = 0) -> int:
    """Forward model: total ESP length (SPI+Seq+payload) for a plaintext of `inner_len` bytes under candidate c."""
    p = inner_len + tfc_pad
    pad = (-(p + 2)) % c.block
    return 8 + c.iv + p + pad + 2 + c.icv
