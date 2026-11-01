"""TCP resets: refused connections (service down / closed port) and connections cut mid-stream."""
from __future__ import annotations

from collections import Counter
from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import ACK, FIN, RST, SYN, PacketView
from .base import Detector

MAX_PENDING = 20_000


class TcpResetDetector(Detector):
    name = "tcp_reset"

    def __init__(self) -> None:
        super().__init__()
        self.state: dict[tuple, str] = {}  # (client, cport, server, sport) -> syn/synack/est
        self.refused: dict[tuple[str, int], dict[str, Any]] = {}  # (server, port) -> stats
        self.refused_targets: dict[str, set[tuple[str, int]]] = {}  # client -> (server, port) refused
        self.cut: dict[str, dict[str, Any]] = {}  # rst sender -> stats
        self.ttl: dict[str, Counter[int]] = {}  # sender -> TTLs of its normal packets

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if not pkt.tcp:
            return
        sport, dport, flags, *_rest = pkt.tcp
        src, dst = pkt.ip_src, pkt.ip_dst
        if not flags & RST:
            ttls = self.ttl.get(src)
            if ttls is None and len(self.ttl) < ctx.cfg["max_hosts"]:
                ttls = self.ttl[src] = Counter()
            if ttls is not None and len(ttls) < 32:
                ttls[pkt.ttl] += 1
        fwd, rev = (src, sport, dst, dport), (dst, dport, src, sport)
        if flags & SYN and not flags & ACK:
            if len(self.state) < MAX_PENDING:
                self.state[fwd] = "syn"
            return
        if flags & SYN and flags & ACK:
            if self.state.get(rev) == "syn":
                self.state[rev] = "synack"
            return
        if flags & RST:
            st = self.state.get(rev)  # RST from the server side of a connection we saw start
            if st == "syn":
                self._refused(pkt, src, sport, dst, ts, frame_no, ctx)
                self.state.pop(rev, None)
                return
            if st == "est" or self.state.get(fwd) == "est":
                self._cut(pkt, src, dst, ts, frame_no, ctx)
            self.state.pop(rev, None)
            self.state.pop(fwd, None)
            return
        if flags & FIN:  # orderly close: stop tracking
            self.state.pop(fwd, None)
            self.state.pop(rev, None)
            return
        if self.state.get(fwd) == "synack" and flags & ACK:
            self.state[fwd] = "est"
        elif self.state.get(rev) == "synack":
            self.state[rev] = "est"

    def _refused(self, pkt: PacketView, server: str, port: int, client: str, ts: float, frame: int,
                 ctx: Context) -> None:
        key = (server, port)
        if key not in self.refused and len(self.refused) >= 5000:
            return
        s = self.refused.setdefault(key, {"clients": set(), "attempts": 0, "first": ts, "last": ts, "frames": []})
        s["attempts"] += 1
        s["last"] = ts
        if len(s["clients"]) < 500:
            s["clients"].add(client)
        if len(s["frames"]) < 150:
            s["frames"].append(frame)
            ctx.remember(pkt)
        targets = self.refused_targets.setdefault(client, set()) if len(self.refused_targets) < 5000 else set()
        if len(targets) < 1000:
            targets.add(key)

    def _cut(self, pkt: PacketView, sender: str, peer: str, ts: float, frame: int, ctx: Context) -> None:
        if sender not in self.cut and len(self.cut) >= 5000:
            return
        s = self.cut.setdefault(sender, {"count": 0, "peers": set(), "first": ts, "last": ts, "frames": [],
                                         "ttls": Counter()})
        s["count"] += 1
        s["last"] = ts
        s["ttls"][pkt.ttl] += 1
        if len(s["peers"]) < 200:
            s["peers"].add(peer)
        if len(s["frames"]) < 150:
            s["frames"].append(frame)
            ctx.remember(pkt)

    def finish(self, ctx: Context) -> list[Finding]:
        cfg = ctx.cfg
        # clients refused on many different ports are scanners: the port-scan detector reports them
        scanners = {c for c, t in self.refused_targets.items() if len(t) >= cfg["scan_min_ports"]}
        findings = []
        for (server, port), s in self.refused.items():
            clients = s["clients"] - scanners
            if not clients:
                continue
            attempts = s["attempts"] if not scanners & s["clients"] else len(clients)
            if len(clients) < cfg["rst_service_min_clients"] and attempts < cfg["rst_service_min_attempts"]:
                continue
            f = Finding(
                id=self.new_id(), kind="service_refused", category="fault",
                hosts=[server] + sorted(clients)[:20], time_start=s["first"], time_end=s["last"],
                wireshark_filter=f"ip.src == {server} && tcp.srcport == {port} && tcp.flags.reset == 1",
                details={"server": server, "port": port, "clients": sorted(clients)[:50],
                         "client_count": len(clients), "attempts": attempts},
            )
            f.add_evidence(s["frames"])
            findings.append(f)
        for sender, s in self.cut.items():
            if sender in scanners or s["count"] < cfg["rst_midstream_min"]:
                continue
            normal = self.ttl.get(sender, Counter())
            normal_ttl = normal.most_common(1)[0][0] if normal else None
            rst_ttl = s["ttls"].most_common(1)[0][0]
            f = Finding(
                id=self.new_id(), kind="connection_resets", category="fault",
                hosts=[sender] + sorted(s["peers"])[:20], time_start=s["first"], time_end=s["last"],
                wireshark_filter=f"ip.src == {sender} && tcp.flags.reset == 1",
                details={"sender": sender, "count": s["count"], "peers": sorted(s["peers"])[:50],
                         "normal_ttl": normal_ttl, "rst_ttl": rst_ttl,
                         "ttl_jump": abs(rst_ttl - normal_ttl) if normal_ttl is not None else 0},
            )
            f.add_evidence(s["frames"])
            findings.append(f)
        return findings
