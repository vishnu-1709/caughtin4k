"""Unusual delays: slow TCP handshakes (SYN -> SYN-ACK) and slow DNS answers, relative to this capture."""
from __future__ import annotations

from statistics import median
from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import ACK, SYN, PacketView
from .base import Detector

MAX_PENDING = 20_000
MAX_SAMPLES = 50_000


class DelayDetector(Detector):
    name = "delays"

    def __init__(self) -> None:
        super().__init__()
        self.syns: dict[tuple, tuple[float, int]] = {}
        self.dnsq: dict[tuple, tuple[float, int]] = {}
        self.samples: dict[str, list[tuple[str, float, int, int, float]]] = {"tcp": [], "dns": []}

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if pkt.tcp:
            sport, dport, flags, *_ = pkt.tcp
            if flags & SYN and not flags & ACK:
                key = (pkt.ip_src, sport, pkt.ip_dst, dport)
                if key not in self.syns and len(self.syns) < MAX_PENDING:
                    self.syns[key] = (ts, frame_no)  # keep the FIRST SYN: retries count as delay
            elif flags & SYN and flags & ACK:
                first = self.syns.pop((pkt.ip_dst, dport, pkt.ip_src, sport), None)
                if first:
                    self._sample("tcp", pkt.ip_src, ts - first[0], first[1], frame_no, ts, pkt, ctx)
        elif pkt.dns and pkt.dns["qname"]:
            d = pkt.dns
            if not d["qr"]:
                key = (pkt.ip_src, d["id"], d["qname"])
                if key not in self.dnsq and len(self.dnsq) < MAX_PENDING:
                    self.dnsq[key] = (ts, frame_no)
            else:
                first = self.dnsq.pop((pkt.ip_dst, d["id"], d["qname"]), None)
                if first:
                    self._sample("dns", pkt.ip_src, ts - first[0], first[1], frame_no, ts, pkt, ctx)

    def _sample(self, kind: str, server: str, rtt: float, f1: int, f2: int, ts: float, pkt: PacketView,
                ctx: Context) -> None:
        if rtt < 0 or len(self.samples[kind]) >= MAX_SAMPLES:
            return
        self.samples[kind].append((server, rtt, f1, f2, ts))
        floor = ctx.cfg["delay_floor_tcp" if kind == "tcp" else "delay_floor_dns"]
        if rtt >= floor:  # potentially slow: keep the packets for evidence
            ctx.remember(pkt, info=None)

    def finish(self, ctx: Context) -> list[Finding]:
        cfg = ctx.cfg
        findings = []
        for kind in ("tcp", "dns"):
            samples = self.samples[kind]
            if len(samples) < cfg["delay_min_samples"]:
                continue
            med = median(s[1] for s in samples)
            floor = cfg["delay_floor_tcp" if kind == "tcp" else "delay_floor_dns"]
            threshold = max(cfg["delay_factor"] * med, floor)
            by_server: dict[str, list] = {}
            for s in samples:
                by_server.setdefault(s[0], []).append(s)
            for server, ss in by_server.items():
                slow = [s for s in ss if s[1] > threshold]
                if len(slow) < cfg["delay_min_slow"] or len(slow) / len(ss) < 0.3:
                    continue
                findings.append(self._finding(kind, server, ss, slow, med, threshold))
            if kind == "tcp" and med >= cfg["delay_absolute_slow_tcp"] and len(by_server) > 1:
                findings.append(self._finding("tcp_all", "many servers", samples,
                                              [s for s in samples if s[1] >= cfg["delay_absolute_slow_tcp"]],
                                              med, cfg["delay_absolute_slow_tcp"]))
        return findings

    def _finding(self, kind: str, server: str, ss: list, slow: list, med: float, threshold: float) -> Finding:
        rtts = sorted(s[1] for s in slow)
        frames: list[int] = []
        for s in slow[:60]:
            frames += [s[2], s[3]]
        details: dict[str, Any] = {
            "measure": "dns" if kind == "dns" else "tcp", "server": server, "samples": len(ss),
            "slow": len(slow), "median_ms": round(med * 1000), "threshold_ms": round(threshold * 1000),
            "slow_median_ms": round(median(rtts) * 1000), "worst_ms": round(rtts[-1] * 1000),
            "network_wide": kind == "tcp_all",
        }
        if kind == "dns":
            wf = f"ip.src == {server} && dns.time > {threshold:.2f}"
        elif kind == "tcp_all":
            wf = f"tcp.flags.syn == 1 && tcp.flags.ack == 1 && tcp.time_delta > {threshold:.2f}"
        else:
            wf = f"ip.src == {server} && tcp.flags.syn == 1 && tcp.flags.ack == 1"
        f = Finding(id=self.new_id(), kind="slow_dns" if kind == "dns" else "slow_responses", category="fault",
                    hosts=[server] if kind != "tcp_all" else [], time_start=min(s[4] for s in slow),
                    time_end=max(s[4] for s in slow), wireshark_filter=wf, details=details)
        f.add_evidence(frames)
        return f
