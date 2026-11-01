"""Detector interface: feed() sees every packet once, finish() returns findings."""
from __future__ import annotations

from ..context import Context
from ..findings import Finding
from ..loader import PacketView


class Detector:
    """Base class. Subclasses keep only bounded state (see Context.cfg caps)."""

    name: str = "base"
    #: checks this detector needs: "mac" (Ethernet/ARP info) or "ip"
    needs: str = "ip"

    def __init__(self) -> None:
        self._count = 0

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        raise NotImplementedError

    def finish(self, ctx: Context) -> list[Finding]:
        raise NotImplementedError

    def new_id(self) -> str:
        self._count += 1
        return f"{self.name}-{self._count}"
