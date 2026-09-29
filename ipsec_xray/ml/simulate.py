"""Traffic simulator: produces inner-packet event streams for eight application classes and frames them as ESP.

The event stream is a list of (t, direction, inner_len) where direction is 'up' (initiator -> responder) or 'down'.
Inner lengths are IPv4 packet lengths (tunnel mode plaintext); transport mode strips the 20-byte IP header.
Used both for the built-in PCAP scenarios and for training the ML models (the lab testbed replaces this with real
captures when available).
"""
from __future__ import annotations

import random
from typing import Callable

from ..analysis.physics import CAND_BY_KEY, Candidate, esp_length_for

TRAFFIC_CLASSES = ["voip", "video", "web", "email", "chat", "icmp", "file", "ssh"]
CLASS_LABELS = {"voip": "VoIP call (RTP)", "video": "Video streaming", "web": "Web browsing (HTTPS)", "email": "E-mail (SMTP/IMAP)",
                "chat": "Messaging (WhatsApp-like)", "icmp": "ICMP ping", "file": "Bulk file transfer", "ssh": "Interactive shell (SSH)"}

ACK = 52          # IPv4 TCP ACK with timestamps
MSS_FULL = 1400   # typical MSS-limited full segment inside a VPN (1380-1420)


def _full():
    return random.choice([1380, 1392, 1400, 1400, 1400, 1412, 1420])


def gen_voip(duration: float, rng: random.Random) -> list:
    ev = []
    codec = rng.choice(["g711", "g711", "opus", "g729"])
    interval = 0.02
    t = rng.uniform(0, 0.02)
    talk_up, talk_down = True, True
    while t < duration:
        if rng.random() < 0.01:
            talk_up = not talk_up
        if rng.random() < 0.01:
            talk_down = not talk_down
        for d, talking in (("up", talk_up), ("down", talk_down)):
            if codec == "g711":
                size = 200
            elif codec == "g729":
                size = 60
            else:
                size = 40 + rng.choice([40, 48, 60, 72, 84, 96, 110])
            if not talking:
                if rng.random() < 0.125:      # comfort noise every ~160 ms
                    ev.append((t + rng.uniform(0, 0.002), d, 60))
                continue
            ev.append((t + rng.gauss(0, 0.0015), d, size))
        if rng.random() < 0.004:              # RTCP report
            ev.append((t, rng.choice(["up", "down"]), rng.choice([100, 108, 120, 136])))
        t += interval
    return ev


def gen_video(duration: float, rng: random.Random) -> list:
    ev = []
    t = 0.3
    ev.append((0.05, "up", rng.randint(300, 700)))
    ev.append((0.12, "down", _full()))
    while t < duration:
        seg_pkts = rng.randint(120, 400)
        ev.append((t, "up", rng.randint(200, 600)))          # segment request
        tt = t + rng.uniform(0.02, 0.06)
        for i in range(seg_pkts):
            ev.append((tt, "down", _full() if rng.random() > 0.03 else rng.randint(200, 1300)))
            if i % 2 == 1:
                ev.append((tt + 0.0004, "up", ACK))
            tt += rng.uniform(0.0004, 0.0025)
        ev.append((tt, "down", rng.randint(100, 900)))
        t += rng.uniform(1.8, 4.5)
    return ev


def gen_web(duration: float, rng: random.Random) -> list:
    ev = []
    t = 0.2
    while t < duration:
        # TLS handshake
        ev.append((t, "up", rng.randint(250, 600)))
        ev.append((t + 0.03, "down", _full()))
        ev.append((t + 0.031, "down", _full()))
        ev.append((t + 0.032, "down", rng.randint(300, 1200)))
        ev.append((t + 0.034, "up", ACK))
        ev.append((t + 0.06, "up", rng.randint(100, 200)))
        # a few requests per page
        tt = t + 0.1
        for _ in range(rng.randint(2, 8)):
            ev.append((tt, "up", rng.randint(300, 900)))
            npk = rng.randint(3, 60)
            t2 = tt + rng.uniform(0.02, 0.15)
            for i in range(npk):
                ev.append((t2, "down", _full() if i < npk - 1 else rng.randint(120, 1400)))
                if i % 2 == 1:
                    ev.append((t2 + 0.0003, "up", ACK))
                t2 += rng.uniform(0.0005, 0.004)
            tt = t2 + rng.uniform(0.01, 0.4)
        t = tt + rng.uniform(2.0, 12.0)   # think time
    return ev


def gen_email(duration: float, rng: random.Random) -> list:
    ev = []
    t = 0.5
    while t < duration:
        if rng.random() < 0.6:   # send with attachment: bulk uplink
            n = rng.randint(50, 800)
            tt = t
            for i in range(n):
                ev.append((tt, "up", _full()))
                if i % 2 == 1:
                    ev.append((tt + 0.0005, "down", ACK))
                tt += rng.uniform(0.0008, 0.005)
            ev.append((tt, "down", rng.randint(80, 200)))
        else:                    # IMAP fetch: downlink
            n = rng.randint(20, 300)
            ev.append((t, "up", rng.randint(80, 250)))
            tt = t + 0.05
            for i in range(n):
                ev.append((tt, "down", _full() if rng.random() > 0.05 else rng.randint(200, 1300)))
                if i % 2 == 1:
                    ev.append((tt + 0.0004, "up", ACK))
                tt += rng.uniform(0.0006, 0.004)
        t += rng.uniform(8.0, 40.0)
    return ev


def gen_chat(duration: float, rng: random.Random) -> list:
    ev = []
    t = 0.3
    next_keepalive = rng.uniform(20, 40)
    while t < duration:
        if t >= next_keepalive:
            ev.append((next_keepalive, "up", rng.choice([60, 68, 76])))
            ev.append((next_keepalive + rng.uniform(0.05, 0.3), "down", rng.choice([60, 68, 76])))
            next_keepalive += rng.uniform(25, 45)
        r = rng.random()
        if r < 0.75:     # text message + ack + receipts
            d = rng.choice(["up", "down"])
            o = "down" if d == "up" else "up"
            ev.append((t, d, rng.randint(110, 420)))
            ev.append((t + rng.uniform(0.1, 0.9), o, rng.randint(90, 200)))
            if rng.random() < 0.5:
                ev.append((t + rng.uniform(1, 4), o, rng.randint(90, 160)))
        elif r < 0.9:    # typing indicator
            ev.append((t, rng.choice(["up", "down"]), rng.randint(80, 110)))
        else:            # picture / voice note
            d = rng.choice(["up", "down"])
            o = "down" if d == "up" else "up"
            n = rng.randint(15, 120)
            tt = t
            for i in range(n):
                ev.append((tt, d, _full()))
                if i % 2 == 1:
                    ev.append((tt + 0.0004, o, ACK))
                tt += rng.uniform(0.001, 0.006)
        t += rng.expovariate(1 / 6.0)
    return ev


def gen_icmp(duration: float, rng: random.Random) -> list:
    ev = []
    size = rng.choice([84, 84, 84, 60, 92, 1028])   # linux default, windows default, custom
    t = rng.uniform(0, 1)
    while t < duration:
        ev.append((t, "up", size))
        ev.append((t + rng.uniform(0.004, 0.06), "down", size))
        t += 1.0 + rng.gauss(0, 0.004)
    return ev


def gen_file(duration: float, rng: random.Random) -> list:
    ev = []
    d = rng.choice(["down", "down", "up"])
    o = "up" if d == "down" else "down"
    t = 0.2
    ev.append((0.05, "up", rng.randint(80, 300)))
    while t < duration:
        ev.append((t, d, _full()))
        if rng.random() < 0.5:
            ev.append((t + 0.0002, o, ACK))
        t += rng.uniform(0.0005, 0.0035)
        if rng.random() < 0.002:      # short stall
            t += rng.uniform(0.05, 0.4)
    return ev


def gen_ssh(duration: float, rng: random.Random) -> list:
    ev = []
    t = 0.5
    while t < duration:
        if rng.random() < 0.85:    # keystroke + echo
            ev.append((t, "up", rng.choice([76, 84, 88, 92, 100])))
            ev.append((t + rng.uniform(0.01, 0.08), "down", rng.choice([76, 84, 92, 100, 116, 132])))
            t += rng.uniform(0.08, 0.9)
        else:                      # command output burst
            n = rng.randint(2, 40)
            tt = t
            for i in range(n):
                ev.append((tt, "down", _full() if i < n - 1 and rng.random() < 0.7 else rng.randint(100, 1200)))
                if i % 2 == 1:
                    ev.append((tt + 0.0003, "up", ACK))
                tt += rng.uniform(0.0006, 0.005)
            t = tt + rng.uniform(0.5, 3.0)
    return ev


GENERATORS: dict[str, Callable[[float, random.Random], list]] = {
    "voip": gen_voip, "video": gen_video, "web": gen_web, "email": gen_email, "chat": gen_chat, "icmp": gen_icmp,
    "file": gen_file, "ssh": gen_ssh,
}


def simulate(cls: str, duration: float, seed: int | None = None, ipver: int = 4) -> list:
    rng = random.Random(seed)
    ev = GENERATORS[cls](duration, rng)
    if ipver == 6:
        ev = [(t, d, n + 20) for t, d, n in ev]
    ev.sort(key=lambda e: e[0])
    return ev


def frame_esp(events: list, cand: Candidate, mode: str = "tunnel", ipver: int = 4, tfc: bool = False,
              loss: float = 0.0, seed: int | None = None) -> list:
    """Turn inner events into ESP (t, dir, total_len) using the forward physics model."""
    rng = random.Random(seed)
    out = []
    hdr = 20 if ipver == 4 else 40
    for ev in events:
        t, d, inner = ev[0], ev[1], ev[2]
        if loss and rng.random() < loss:
            continue
        p = inner if mode == "tunnel" else max(8, inner - hdr)
        pad = 0
        if tfc:
            pad = max(0, 1400 - p) if rng.random() < 0.5 else 0
        out.append((t, d, esp_length_for(p, cand, pad)) + tuple(ev[3:]))
    return out


def candidate(key: str) -> Candidate:
    return CAND_BY_KEY[key]
