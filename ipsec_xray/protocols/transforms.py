"""IKE transform and proposal representations and IANA registry decoders."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import registry as R


@dataclass
class Transform:
    ttype: int
    tid: int
    name: str
    keylen: Optional[int] = None
    attrs: dict = field(default_factory=dict)

    @property
    def ttype_name(self) -> str:
        return R.IKEV2_TRANSFORM_TYPES.get(self.ttype, f"T{self.ttype}")

    def label(self) -> str:
        return f"{self.name}-{self.keylen}" if self.keylen else self.name


@dataclass
class Proposal:
    number: int
    protocol: int  # 1 IKE, 2 AH, 3 ESP
    spi: bytes
    transforms: list[Transform] = field(default_factory=list)
    v1_attrs: dict = field(default_factory=dict)  # IKEv1 phase-1 preferred transform attributes (decoded)
    v1_transforms: list = field(default_factory=list)  # all IKEv1 transforms (decoded attribute dicts)

    @property
    def protocol_name(self) -> str:
        return {1: "IKE", 2: "AH", 3: "ESP"}.get(self.protocol, f"P{self.protocol}")

    def by_type(self, ttype: int) -> list[Transform]:
        return [t for t in self.transforms if t.ttype == ttype]

    def summary(self) -> str:
        parts = []
        for tt in (1, 2, 3, 4, 6, 5):
            names = [t.label() for t in self.by_type(tt)]
            if names:
                parts.append(f"{R.IKEV2_TRANSFORM_TYPES.get(tt, tt)}={'/'.join(names)}")
        if self.v1_transforms:
            parts = [" | ".join(", ".join(f"{k}={v}" for k, v in t.items()) for t in self.v1_transforms)]
        return f"{self.protocol_name}#{self.number}: " + " ".join(parts)


def v2_transform_name(ttype: int, tid: int) -> str:
    """Resolve transform type and ID to human-readable RFC/IANA name."""
    if ttype == 1:
        return R.IKEV2_ENCR.get(tid, (f"ENCR_{tid}",))[0]
    if ttype == 2:
        return R.IKEV2_PRF.get(tid, (f"PRF_{tid}",))[0]
    if ttype == 3:
        return R.IKEV2_INTEG.get(tid, (f"INTEG_{tid}",))[0]
    if ttype == 4 or 6 <= ttype <= 12:
        return R.DH_GROUPS.get(tid, (f"DH_{tid}",))[0]
    if ttype == 5:
        return {0: "NO_ESN", 1: "ESN"}.get(tid, f"ESN_{tid}")
    return f"T{ttype}_{tid}"
