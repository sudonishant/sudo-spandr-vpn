"""Security Association (SA) records, SPI correlation, and Child-SA lineage tracking."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChildSA:
    spi_in: int
    spi_out: Optional[int] = None
    protocol: str = "ESP"
    mode: str = "tunnel"
    encryption: Optional[str] = None
    integrity: Optional[str] = None
    dh_group: Optional[int] = None
    created_at: float = 0.0


@dataclass
class IKESARecord:
    spi_i: str
    spi_r: str
    version: int
    initiator_ip: str
    responder_ip: str
    initiator_port: int = 500
    responder_port: int = 500
    nat_detected: bool = False
    pfs_group: Optional[int] = None
    cipher: Optional[str] = None
    integrity: Optional[str] = None
    prf: Optional[str] = None
    child_sas: list[ChildSA] = field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.spi_i[:8]}:{self.spi_r[:8]}"

    def add_child(self, child: ChildSA) -> None:
        self.child_sas.append(child)
