"""ARP spoofing, duplicate IP addresses and ARP conflicts (one IP claimed by several MACs).

The detector only collects facts; the judge decides attack vs fault.
"""
from __future__ import annotations

from typing import Any

from ..context import Context, ip_kind, is_unicast_mac
from ..findings import Finding
from ..loader import PacketView
from .base import Detector

FAILOVER_PREFIXES = ("00:00:5e:00:01", "00:00:5e:00:02", "00:00:0c:07:ac", "00:00:0c:9f:f")  # VRRP / HSRP


class ArpDetector(Detector):
    name = "arp"
    needs = "mac"

    def __init__(self) -> None:
        super().__init__()
        self.claims: dict[str, dict[str, dict[str, Any]]] = {}  # ip -> mac -> stats
        self.last_mac: dict[str, str] = {}
        self.flips: dict[str, int] = {}
        self.requests: dict[str, float] = {}  # target ip -> last time someone asked for it
        self.probes: dict[str, tuple[float, str, int]] = {}  # ip -> (ts, prober mac, frame)
        self.dad_conflicts: dict[str, list[int]] = {}  # ip -> frames
        self.max_ips = 4096

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if not pkt.arp:
            return
        op, hwsrc, psrc, _hwdst, pdst = pkt.arp
        ctx.remember(pkt)
        if op == 1:
            if psrc == "0.0.0.0":  # ARP probe: "is this address free?"
                if len(self.probes) < self.max_ips:
                    self.probes[pdst] = (ts, hwsrc or "", frame_no)
                return
            if len(self.requests) < self.max_ips or pdst in self.requests:
                self.requests[pdst] = ts
            self._claim(psrc, hwsrc, pkt, ts, frame_no, kind="gratuitous" if psrc == pdst else "request",
                        unsolicited=False)
        elif op == 2:
            asked = self.requests.get(psrc)
            solicited = asked is not None and 0 <= ts - asked <= ctx.cfg["arp_solicit_window"]
            self._claim(psrc, hwsrc, pkt, ts, frame_no, kind="reply", unsolicited=not solicited)
            probe = self.probes.get(psrc)
            if probe and hwsrc != probe[1] and 0 <= ts - probe[0] <= ctx.cfg["arp_solicit_window"]:
                self.dad_conflicts.setdefault(psrc, []).extend([probe[2], frame_no])

    def _claim(self, ip: str, mac: str | None, pkt: PacketView, ts: float, frame: int, kind: str,
               unsolicited: bool) -> None:
        if not mac or not is_unicast_mac(mac) or ip_kind(ip) != "private":
            return
        if ip not in self.claims and len(self.claims) >= self.max_ips:
            return
        macs = self.claims.setdefault(ip, {})
        if mac not in macs and len(macs) >= 8:
            return
        s = macs.setdefault(mac, {"count": 0, "first": ts, "last": ts, "frames": [], "replies": 0,
                                  "unsolicited": 0, "gratuitous": 0, "eth_mismatch": 0, "targets": set()})
        s["count"] += 1
        s["last"] = ts
        if len(s["frames"]) < 150:
            s["frames"].append(frame)
        if kind == "reply":
            s["replies"] += 1
            s["unsolicited"] += int(unsolicited)
            if pkt.arp and len(s["targets"]) < 50:
                s["targets"].add(pkt.arp[4])
        elif kind == "gratuitous":
            s["gratuitous"] += 1
        if pkt.eth_src and pkt.eth_src != mac:
            s["eth_mismatch"] += 1
        if self.last_mac.get(ip) not in (None, mac):
            self.flips[ip] = self.flips.get(ip, 0) + 1
        self.last_mac[ip] = mac

    def _original(self, ip: str, macs: dict[str, dict[str, Any]], ctx: Context) -> str:
        """The MAC that most plausibly owns the IP: real IP traffic first, then earliest claim."""
        traffic = ctx.ip_traffic_macs.get(ip, {})
        return min(macs, key=lambda m: (-traffic.get(m, 0), macs[m]["first"]))

    def finish(self, ctx: Context) -> list[Finding]:
        # 1) collect conflicts per IP, 2) group them by the newcomer MAC (one impostor = one finding)
        by_newcomer: dict[str, list[tuple[str, str]]] = {}
        for ip, macs in self.claims.items():
            if len(macs) < 2:
                continue
            original = self._original(ip, macs, ctx)
            for mac in macs:
                if mac != original:
                    by_newcomer.setdefault(mac, []).append((ip, original))

        findings = []
        for mac, pairs in by_newcomer.items():
            ips = sorted({ip for ip, _ in pairs})
            originals = {ip: orig for ip, orig in pairs}
            stats = [self.claims[ip][mac] for ip in ips]
            all_claimed = set(ctx.arp_claims.get(mac, {}))
            own_ips = sorted(i for i in all_claimed if i not in ips)
            first = min(s["first"] for s in stats)
            last = max(max(s["last"] for s in stats), first)
            count = sum(s["count"] for s in stats)
            replies = sum(s["replies"] for s in stats)
            unsolicited = sum(s["unsolicited"] for s in stats)
            minutes = max((last - first) / 60.0, 1 / 60)
            traffic = {ip: dict(ctx.ip_traffic_macs.get(ip, {})) for ip in ips}
            frames = [f for s in stats for f in s["frames"]]
            for ip in ips:
                frames += self.claims[ip][originals[ip]]["frames"][:15]
                frames += self.dad_conflicts.get(ip, [])
            targets = sorted({t for ip in ips for t in self.claims[ip][mac]["targets"] if t != ip})
            gateway = ctx.gateway_ip in ips if ctx.gateway_ip else False
            f = Finding(
                id=self.new_id(), kind="ip_conflict", category="attack" if gateway or unsolicited else "fault",
                hosts=ips + [mac] + sorted(set(originals.values())) + own_ips,
                time_start=first, time_end=last,
                wireshark_filter=" || ".join(f"arp.src.proto_ipv4 == {ip}" for ip in ips),
                details={
                    "ips": ips, "new_mac": mac, "original_macs": originals, "own_ips": own_ips,
                    "gateway_involved": gateway, "claims": count, "replies": replies,
                    "unsolicited": unsolicited, "rate_per_min": round(count / minutes, 1),
                    "flips": sum(self.flips.get(ip, 0) for ip in ips),
                    "eth_mismatch": sum(s["eth_mismatch"] for s in stats),
                    "gratuitous": sum(s["gratuitous"] for s in stats),
                    "dad_conflicts": sum(len(self.dad_conflicts.get(ip, [])) // 2 for ip in ips),
                    "both_send_traffic": all(mac in traffic[ip] and originals[ip] in traffic[ip] for ip in ips),
                    "failover_mac": any(m.startswith(FAILOVER_PREFIXES) for m in [mac, *originals.values()]),
                    "targets": targets[:20],
                },
            )
            f.add_evidence(frames)
            findings.append(f)
        return findings
