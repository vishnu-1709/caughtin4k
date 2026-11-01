"""MTU mismatches: ICMP 'fragmentation needed', and silent black holes (big DF packets never get through)."""
from __future__ import annotations

from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import ACK, PacketView
from .base import Detector

LARGE = 1400  # IP packet size we treat as "big"
MAX_FLOWS = 20_000


class MtuDetector(Detector):
    name = "mtu"

    def __init__(self) -> None:
        super().__init__()
        self.icmp: dict[tuple[str, int], dict[str, Any]] = {}  # (router, mtu) -> stats
        self.flows: dict[tuple, dict[str, Any]] = {}
        self.oversize = 0  # packets larger than the link allows: NIC offloading in host captures

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if pkt.icmp and pkt.icmp[0] == 3 and pkt.icmp[1] == 4:
            _t, _c, mtu, inner = pkt.icmp
            key = (pkt.ip_src, mtu)
            if key not in self.icmp and len(self.icmp) >= 500:
                return
            s = self.icmp.setdefault(key, {"count": 0, "senders": set(), "dests": set(), "first": ts, "last": ts,
                                           "frames": [], "sizes": set()})
            s["count"] += 1
            s["last"] = ts
            if inner:
                if len(s["senders"]) < 100:
                    s["senders"].add(inner[0])
                    s["dests"].add(inner[1])
                s["sizes"].add(inner[2])
            if len(s["frames"]) < 100:
                s["frames"].append(frame_no)
                ctx.remember(pkt)
            return
        if not pkt.tcp or pkt.ip_ver != 4:
            return
        if pkt.length > ctx.cfg["mtu_link"] + 4 or pkt.ip_len > ctx.cfg["mtu_link"] - 14 + 4:
            self.oversize += 1  # bigger than the wire allows: the capture saw pre-offload segments
            return
        sport, dport, flags, seq, ack, _win, plen = pkt.tcp
        fwd, rev = (pkt.ip_src, sport, pkt.ip_dst, dport), (pkt.ip_dst, dport, pkt.ip_src, sport)
        if flags & ACK and rev in self.flows:
            r = self.flows[rev]
            r["max_ack"] = max(r["max_ack"], ack) if r["max_ack"] is not None else ack
        if plen <= 1:
            return
        f = self.flows.get(fwd)
        if f is None:
            if len(self.flows) >= MAX_FLOWS:
                return
            f = self.flows[fwd] = {"large": {}, "large_retrans": 0, "small_sent": 0, "first_seq": seq,
                                   "max_ack": None, "frames": [], "first": ts, "last": ts, "df": True,
                                   "max_size": 0}
        f["last"] = ts
        if pkt.ip_len >= LARGE:
            f["max_size"] = max(f["max_size"], pkt.ip_len)
            f["df"] = f["df"] and pkt.ip_df
            if seq in f["large"]:
                f["large_retrans"] += 1
                if len(f["frames"]) < 60:
                    f["frames"].append(frame_no)
                    ctx.remember(pkt, info=f"Retransmission of a {pkt.ip_len}-byte DF packet, Seq={seq}")
            elif len(f["large"]) < 2000:
                f["large"][seq] = seq + plen
                if len(f["frames"]) < 60:
                    f["frames"].append(frame_no)
                    ctx.remember(pkt)
        else:
            f["small_sent"] += 1

    def finish(self, ctx: Context) -> list[Finding]:
        findings = []
        for (router, mtu), s in self.icmp.items():
            if s["count"] < 1:
                continue
            f = Finding(
                id=self.new_id(), kind="mtu_mismatch", category="fault",
                hosts=[router] + sorted(s["senders"])[:10] + sorted(s["dests"])[:10],
                time_start=s["first"], time_end=s["last"],
                wireshark_filter=f"icmp.type == 3 && icmp.code == 4 && ip.src == {router}",
                details={"mode": "icmp", "router": router, "mtu": mtu, "count": s["count"],
                         "senders": sorted(s["senders"])[:10], "dests": sorted(s["dests"])[:10],
                         "sizes": sorted(s["sizes"])[-3:], "router_is_local": router == ctx.gateway_ip or
                         router.startswith(("10.", "192.168.", "172."))},
            )
            f.add_evidence(s["frames"])
            findings.append(f)
        icmp_victims = {v for s in self.icmp.values() for v in s["senders"]}
        for (src, sport, dst, dport), fl in self.flows.items():
            large_ends = list(fl["large"].values())
            if fl["large_retrans"] < 3 or not large_ends or not fl["df"] or src in icmp_victims:
                continue
            acked_large = fl["max_ack"] is not None and any(fl["max_ack"] >= e for e in large_ends)
            small_ok = fl["small_sent"] > 0 and fl["max_ack"] is not None and fl["max_ack"] > fl["first_seq"]
            if acked_large or not small_ok:
                continue
            f = Finding(
                id=self.new_id(), kind="mtu_mismatch", category="fault", hosts=[src, dst],
                time_start=fl["first"], time_end=fl["last"],
                wireshark_filter=f"ip.addr == {src} && ip.addr == {dst} && ip.flags.df == 1 && ip.len >= {LARGE}",
                details={"mode": "blackhole", "src": src, "dst": dst, "port": dport,
                         "large_retrans": fl["large_retrans"], "max_size": fl["max_size"],
                         "small_sent": fl["small_sent"]},
            )
            f.add_evidence(fl["frames"])
            findings.append(f)
        if self.oversize >= 5:
            ctx.extra_notes.append(
                f"{self.oversize:,} packets were larger than the network allows: this capture was taken on a "
                "computer whose network card combines packets (offloading). That is normal and was not treated "
                "as an MTU problem.")
        return findings
