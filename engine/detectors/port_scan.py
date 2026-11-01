"""Port scans: one source probing many ports/hosts quickly, with few real conversations."""
from __future__ import annotations

from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import ACK, RST, SYN, PacketView
from .base import Detector

MAX_SOURCES = 2000
MAX_PROBES = 5000


class PortScanDetector(Detector):
    name = "port_scan"

    def __init__(self) -> None:
        super().__init__()
        self.probes: dict[str, list[tuple[float, str, int, int]]] = {}  # src -> (ts, dst, dport, frame)
        self.outcome: dict[tuple[str, str, int], str] = {}  # (src, dst, dport) -> open/closed/completed
        self.half_open = 0
        self.half_open_by: dict[str, int] = {}

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if not pkt.tcp:
            return
        sport, dport, flags, _seq, _ack, _win, plen = pkt.tcp
        src, dst = pkt.ip_src, pkt.ip_dst
        if flags & SYN and not flags & ACK:
            lst = self.probes.get(src)
            if lst is None:
                if len(self.probes) >= MAX_SOURCES:
                    return
                lst = self.probes[src] = []
            if len(lst) < MAX_PROBES:
                lst.append((ts, dst, dport, frame_no))
                ctx.remember(pkt)
            return
        if len(self.outcome) > 200_000:
            return
        if flags & SYN and flags & ACK:  # target answered: port open
            self.outcome.setdefault((dst, src, sport), "open")
        elif flags & RST:
            key_target = (dst, src, sport)  # RST from target: closed
            if key_target in self.outcome or dst in self.probes:
                if self.outcome.get(key_target) is None:
                    self.outcome[key_target] = "closed"
                    if len(self.probes.get(dst, [])) < MAX_PROBES:
                        ctx.remember(pkt)
            key_scanner = (src, dst, dport)  # RST from scanner right after SYN-ACK: half-open scan
            if self.outcome.get(key_scanner) == "open":
                self.half_open_by[src] = self.half_open_by.get(src, 0) + 1
        elif plen > 0 and (src, dst, dport) in self.outcome:
            self.outcome[(src, dst, dport)] = "completed"

    def finish(self, ctx: Context) -> list[Finding]:
        cfg = ctx.cfg
        findings = []
        for src, probes in self.probes.items():
            if len(probes) < min(cfg["scan_min_ports"], cfg["scan_min_hosts"]):
                continue
            stats = self._window(probes, cfg["scan_window"])
            vertical = stats["max_ports_one_host"] >= cfg["scan_min_ports"]
            horizontal = stats["max_hosts_one_port"] >= cfg["scan_min_hosts"]
            if not (vertical or horizontal):
                continue
            targets = {(d, p) for _, d, p, _ in probes}
            outcomes = [self.outcome.get((src, d, p), "none") for d, p in targets]
            completed = outcomes.count("completed")
            completion = completed / max(len(targets), 1)
            if completion > cfg["scan_max_completion"]:
                continue  # many real conversations: a busy client, not a scan
            hosts = sorted({d for d, _ in targets})
            ports = sorted({p for _, p in targets})
            focus = stats["main_target"] if vertical else None
            open_ports = sorted({p for (d, p), o in zip(targets, outcomes)
                                 if o in ("open", "completed") and (focus is None or d == focus)})
            first, last = probes[0][0], probes[-1][0]
            duration = max(last - first, 0.001)
            seq_ports = sum(1 for a, b in zip(ports, ports[1:]) if b == a + 1)
            f = Finding(
                id=self.new_id(), kind="port_scan", category="attack",
                hosts=[src] + hosts[:20], time_start=first, time_end=last,
                wireshark_filter=f"ip.src == {src} && tcp.flags.syn == 1 && tcp.flags.ack == 0",
                details={
                    "scanner": src, "targets": hosts[:50], "target_count": len(hosts),
                    "ports_tried": len(ports), "attempts": len(probes), "open_ports": open_ports[:30],
                    "closed": outcomes.count("closed"), "no_reply": outcomes.count("none"),
                    "completed": completed, "completion": round(completion, 3),
                    "failure_ratio": round((outcomes.count("closed") + outcomes.count("none")) / max(len(targets), 1), 3),
                    "rate": round(len(probes) / duration, 1), "duration": round(duration, 1),
                    "sequential_ratio": round(seq_ports / max(len(ports) - 1, 1), 2),
                    "half_open": self.half_open_by.get(src, 0),
                    "vertical": vertical, "horizontal": horizontal, **stats,
                    "sample_ports": ports[:25],
                },
            )
            frames = [fr for *_, fr in probes]
            closed_frames = [n for n, row in ctx.rows.items() if row[1] in hosts and row[2] == src and "RST" in row[4]]
            f.add_evidence(frames[:150] + closed_frames[:50])
            findings.append(f)
        return findings

    @staticmethod
    def _window(probes: list[tuple[float, str, int, int]], window: float) -> dict[str, Any]:
        """Max distinct ports on one host, and hosts on one port, inside any time window."""
        best_ports = best_hosts = 0
        best_target = None
        lo = 0
        per_host: dict[str, dict[int, int]] = {}
        per_port: dict[int, dict[str, int]] = {}
        for hi, (ts, dst, port, _) in enumerate(probes):
            per_host.setdefault(dst, {}).setdefault(port, 0)
            per_host[dst][port] += 1
            per_port.setdefault(port, {}).setdefault(dst, 0)
            per_port[port][dst] += 1
            while ts - probes[lo][0] > window:
                _, d0, p0, _ = probes[lo]
                per_host[d0][p0] -= 1
                if not per_host[d0][p0]:
                    del per_host[d0][p0]
                per_port[p0][d0] -= 1
                if not per_port[p0][d0]:
                    del per_port[p0][d0]
                lo += 1
            if len(per_host[dst]) > best_ports:
                best_ports, best_target = len(per_host[dst]), dst
            best_hosts = max(best_hosts, len(per_port[port]))
        return {"max_ports_one_host": best_ports, "max_hosts_one_port": best_hosts, "main_target": best_target}
