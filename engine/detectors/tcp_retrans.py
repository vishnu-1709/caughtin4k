"""TCP retransmissions: the same data (flow + sequence number) sent again = packet loss."""
from __future__ import annotations

from collections import deque
from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import PacketView
from .base import Detector


class TcpRetransDetector(Detector):
    name = "tcp_retrans"

    def __init__(self) -> None:
        super().__init__()
        self.flows: dict[tuple, dict[str, Any]] = {}

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if not pkt.tcp:
            return
        sport, dport, _flags, seq, _ack, _win, plen = pkt.tcp
        if plen <= 1:  # pure ACKs, keepalives and zero-window probes are not data
            return
        key = (pkt.ip_src, sport, pkt.ip_dst, dport)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= ctx.cfg["max_flows"]:
                return
            flow = self.flows[key] = {"data": 0, "retrans": 0, "seen": set(), "order": deque(),
                                      "first": ts, "last": ts, "frames": [], "first_retrans": None, "seen_by": {}}
        flow["data"] += 1
        flow["last"] = ts
        mark = (seq, plen)
        prev = flow["seen_by"].get(mark)
        if prev is not None and pkt.eth_src and prev[1] and prev[1] != pkt.eth_src and ts - prev[0] < 0.05:
            return  # the same segment re-sent by a different device within ms: a relay's copy, not a loss
        if mark in flow["seen"]:
            flow["retrans"] += 1
            flow["seen_by"][mark] = (ts, pkt.eth_src)  # so the relay's copy of this resend is not counted again
            flow["first_retrans"] = flow["first_retrans"] or ts
            if len(flow["frames"]) < 100:
                flow["frames"].append(frame_no)
                ctx.remember(pkt, info=f"Retransmission: {sport} → {dport} Seq={seq} Len={plen}")
            return
        flow["seen"].add(mark)
        flow["seen_by"][mark] = (ts, pkt.eth_src)
        flow["order"].append(mark)
        if len(flow["order"]) > ctx.cfg["retrans_seq_memory"]:
            old = flow["order"].popleft()
            flow["seen"].discard(old)
            flow["seen_by"].pop(old, None)

    def finish(self, ctx: Context) -> list[Finding]:
        cfg = ctx.cfg
        pairs: dict[tuple[str, str], dict[str, Any]] = {}
        for (src, sport, dst, dport), fl in self.flows.items():
            a, b = sorted((src, dst))
            p = pairs.setdefault((a, b), {"data": 0, "retrans": 0, "flows": 0, "bad_flows": 0, "first": fl["first"],
                                          "last": fl["last"], "frames": [], "senders": set(), "ports": set()})
            p["data"] += fl["data"]
            p["retrans"] += fl["retrans"]
            p["flows"] += 1
            p["first"], p["last"] = min(p["first"], fl["first"]), max(p["last"], fl["last"])
            if fl["retrans"]:
                p["bad_flows"] += 1
                p["senders"].add(src)
                p["ports"].add(min(sport, dport))
                p["frames"].extend(fl["frames"])
                p["first"] = min(p["first"], fl["first_retrans"] or p["first"])
        flagged = [(k, p) for k, p in pairs.items()
                   if p["retrans"] >= cfg["retrans_min_count"] and p["retrans"] / max(p["data"], 1) >= cfg["retrans_min_rate"]]
        flagged.sort(key=lambda kp: -kp[1]["retrans"])
        total_data = sum(p["data"] for p in pairs.values())
        total_retrans = sum(p["retrans"] for p in pairs.values())
        findings = []
        for (a, b), p in flagged[:5]:
            f = Finding(
                id=self.new_id(), kind="tcp_retransmissions", category="fault",
                hosts=[a, b], time_start=p["first"], time_end=p["last"],
                wireshark_filter=f"ip.addr == {a} && ip.addr == {b} && tcp.analysis.retransmission",
                details={"a": a, "b": b, "data_segments": p["data"], "retransmissions": p["retrans"],
                         "rate": round(p["retrans"] / max(p["data"], 1), 3), "flows": p["flows"],
                         "bad_flows": p["bad_flows"], "senders": sorted(p["senders"]),
                         "ports": sorted(p["ports"])[:10], "pairs_flagged": len(flagged),
                         "capture_rate": round(total_retrans / max(total_data, 1), 3),
                         "ack_gaps": ctx.ack_gaps},
            )
            f.add_evidence(p["frames"])
            findings.append(f)
        return findings
