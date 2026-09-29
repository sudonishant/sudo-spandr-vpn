"""Feature extraction for the ML models (traffic class, cipher framing, mode). Pure numpy."""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

from .physics import CANDIDATES, fits, payload_lengths

TRAFFIC_FEATURE_NAMES = [
    "log_n", "log_duration", "log_pps", "log_bps", "size_mean", "size_std", "size_min", "size_max", "size_p10", "size_p25",
    "size_p50", "size_p75", "size_p90", "frac_small", "frac_mid", "frac_large", "up_pkt_ratio", "up_byte_ratio",
    "iat_mean", "iat_std", "iat_cv", "iat_p50", "iat_p90", "iat_lt5ms", "iat_15_25ms", "iat_gt1s", "periodicity",
    "burstiness", "distinct_ratio", "size_entropy", "mode_share", "mean_up", "mean_down", "req_resp", "second_share",
    "frac_ack_like", "frac_full",
]


def traffic_features(pkts: list) -> np.ndarray:
    """pkts: list of (ts, direction('up'/'down'), total_len) sorted by ts."""
    if not pkts:
        return np.zeros(len(TRAFFIC_FEATURE_NAMES))
    ts = np.array([p[0] for p in pkts], dtype=float)
    sizes = np.array([p[2] for p in pkts], dtype=float)
    up = np.array([p[1] == "up" for p in pkts])
    n = len(pkts)
    dur = max(ts[-1] - ts[0], 1e-3)
    f = []
    f += [math.log1p(n), math.log1p(dur), math.log1p(n / dur), math.log1p(sizes.sum() / dur)]
    f += [sizes.mean(), sizes.std(), sizes.min(), sizes.max()] + list(np.percentile(sizes, [10, 25, 50, 75, 90]))
    f += [(sizes < 150).mean(), ((sizes >= 150) & (sizes <= 1200)).mean(), (sizes > 1200).mean()]
    f += [up.mean(), sizes[up].sum() / max(sizes.sum(), 1)]
    if n > 1:
        iat = np.diff(ts)
        iat = np.clip(iat, 0, None)
        med = np.median(iat) if len(iat) else 0.0
        f += [iat.mean(), iat.std(), iat.std() / (iat.mean() + 1e-6), med, np.percentile(iat, 90),
              (iat < 0.005).mean(), ((iat > 0.015) & (iat < 0.025)).mean(), (iat > 1.0).mean(),
              (np.abs(iat - med) <= 0.1 * max(med, 1e-6)).mean() if med > 0 else 0.0]
        bins = np.floor((ts - ts[0]) / 0.2).astype(int)
        counts = np.bincount(bins)
        f += [counts.max() / max(counts.mean(), 1e-6)]
    else:
        f += [0.0] * 10
    cnt = Counter(sizes.astype(int).tolist())
    probs = np.array(list(cnt.values()), dtype=float) / n
    top2 = sorted(cnt.values(), reverse=True)[:2]
    f += [len(cnt) / n, float(-(probs * np.log(probs)).sum()), top2[0] / n]
    f += [sizes[up].mean() if up.any() else 0.0, sizes[~up].mean() if (~up).any() else 0.0]
    # request/response: up packet followed by a down packet within 300 ms
    rr = 0
    ups = 0
    down_ts = ts[~up]
    for i in range(n):
        if up[i]:
            ups += 1
            j = np.searchsorted(down_ts, ts[i])
            if j < len(down_ts) and down_ts[j] - ts[i] <= 0.3:
                rr += 1
    f += [rr / max(ups, 1), (top2[1] / n) if len(top2) > 1 else 0.0]
    f += [((sizes >= 76) & (sizes <= 100)).mean(), (sizes >= 1380).mean()]
    return np.array(f, dtype=float)


CIPHER_FEATURE_NAMES = [f"res16_{i}" for i in range(16)] + [f"fit_{c.key}" for c in CANDIDATES] + \
    ["log_distinct", "min_lp", "min_share", "second_min", "log_n", "frac_le_120", "frac_ge_1400", "res8_4", "res4_0"]


def cipher_features(total_lengths: list[int]) -> np.ndarray:
    lps = payload_lengths(total_lengths)
    if not lps:
        return np.zeros(len(CIPHER_FEATURE_NAMES))
    arr = np.array(lps)
    n = len(arr)
    res16 = np.bincount(arr % 16, minlength=16) / n
    cnt = Counter(lps)
    fitsv = [sum(c for lp, c in cnt.items() if fits(lp, cand)) / n for cand in CANDIDATES]
    smin = int(arr.min())
    uniq = sorted(cnt)
    second = uniq[1] if len(uniq) > 1 else smin
    f = list(res16) + fitsv + [math.log1p(len(cnt)), smin, cnt[smin] / n, second, math.log1p(n), (arr <= 120).mean(),
                               (arr >= 1400).mean(), (arr % 8 == 4).mean(), (arr % 4 == 0).mean()]
    return np.array(f, dtype=float)
