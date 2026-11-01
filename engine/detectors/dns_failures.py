"""DNS failures: unanswered queries (timeouts), SERVFAIL/REFUSED servers, NXDOMAIN storms."""
from __future__ import annotations

import math
from collections import Counter
from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import PacketView
from .base import Detector

MAX_PENDING = 20_000


def entropy(label: str) -> float:
    """Shannon entropy (bits/char) of a DNS label: random names score high."""
    if not label:
        return 0.0
    counts = Counter(label)
    return -sum(c / len(label) * math.log2(c / len(label)) for c in counts.values())


class DnsFailureDetector(Detector):
    name = "dns_failures"

    def __init__(self) -> None:
        super().__init__()
        self.pending: dict[tuple[str, int, str], tuple[float, str, int]] = {}  # -> (ts, server, frame)
        self.servers: dict[str, dict[str, Any]] = {}
        self.nx: dict[str, dict[str, Any]] = {}  # client -> NXDOMAIN stats
        self.client_queries: Counter[str] = Counter()

    def _server(self, ip: str) -> dict[str, Any] | None:
        if ip not in self.servers and len(self.servers) >= 1000:
            return None
        return self.servers.setdefault(ip, {"queries": 0, "answered": 0, "servfail": 0, "refused": 0,
                                            "timeouts": 0, "fail_frames": [], "timeout_frames": [],
                                            "clients": set(), "first": None, "last": None, "times": []})

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        d = pkt.dns
        if not d or not d["qname"]:
            return
        if not d["qr"]:
            s = self._server(pkt.ip_dst)
            if s is None:
                return
            s["queries"] += 1
            if len(s["times"]) < 50_000:
                s["times"].append(ts)
            if len(s["clients"]) < 500:
                s["clients"].add(pkt.ip_src)
            self.client_queries[pkt.ip_src] += 1
            key = (pkt.ip_src, d["id"], d["qname"])
            if len(self.pending) < MAX_PENDING:
                self.pending[key] = (ts, pkt.ip_dst, frame_no)
                ctx.remember(pkt)
            return
        key = (pkt.ip_dst, d["id"], d["qname"])
        query = self.pending.pop(key, None)
        if query is None:
            return
        s = self._server(query[1])
        if s is None:
            return
        s["answered"] += 1
        rc = d["rcode"]
        if rc in (2, 5):
            s["servfail" if rc == 2 else "refused"] += 1
            self._mark(s, ts, frame_no, "fail_frames", query[2], pkt, ctx)
        elif rc == 3:
            n = self.nx.setdefault(pkt.ip_dst, {"count": 0, "names": set(), "frames": [], "first": ts, "last": ts}) \
                if (pkt.ip_dst in self.nx or len(self.nx) < 1000) else None
            if n is not None:
                n["count"] += 1
                n["last"] = ts
                if len(n["names"]) < 300:
                    n["names"].add(d["qname"])
                if len(n["frames"]) < 100:
                    n["frames"].append(frame_no)
                    ctx.remember(pkt)

    @staticmethod
    def _mark(s: dict[str, Any], ts: float, frame: int, key: str, query_frame: int, pkt: PacketView | None,
              ctx: Context) -> None:
        s["first"] = ts if s["first"] is None else min(s["first"], ts)
        s["last"] = ts if s["last"] is None else max(s["last"], ts)
        times = s.setdefault(key + "_ts", [])
        if len(times) < 50_000:
            times.append(ts)
        if len(s[key]) < 120:
            s[key].extend([query_frame, frame] if pkt else [query_frame])
            if pkt:
                ctx.remember(pkt)

    def finish(self, ctx: Context) -> list[Finding]:
        cfg = ctx.cfg
        end = ctx.end or 0
        for (_client, _qid, _name), (ts, server, frame) in self.pending.items():
            if end - ts >= cfg["dns_timeout"]:
                s = self.servers.get(server)
                if s is not None:
                    s["timeouts"] += 1
                    self._mark(s, ts, frame, "timeout_frames", frame, None, ctx)
        findings = []
        for server, s in self.servers.items():
            # failure rate is measured over the period when failures happened, not the whole capture
            if s["first"] is None:
                continue
            q = self._window_queries(s, "timeout_frames_ts")
            if s["timeouts"] >= cfg["dns_min_failures"] and s["timeouts"] / q >= cfg["dns_min_fail_rate"]:
                findings.append(self._finding("dns_timeout", server, s, s["timeouts"], q, s["timeout_frames"],
                                              f"dns && ip.addr == {server} && dns.flags.response == 0 && !dns.response_in"))
            bad = s["servfail"] + s["refused"]
            q = self._window_queries(s, "fail_frames_ts")
            if bad >= cfg["dns_min_failures"] and bad / q >= cfg["dns_min_fail_rate"]:
                findings.append(self._finding("dns_servfail", server, s, bad, q, s["fail_frames"],
                                              f"ip.src == {server} && (dns.flags.rcode == 2 || dns.flags.rcode == 5)"))
        for client, n in self.nx.items():
            total = max(self.client_queries.get(client, 0), 1)
            if n["count"] < cfg["dns_nx_min"] or n["count"] / total < 0.3:
                continue
            names = sorted(n["names"])
            labels = [nm.split(".")[0] for nm in names]
            avg_entropy = sum(entropy(lb) for lb in labels) / max(len(labels), 1)
            avg_len = sum(len(lb) for lb in labels) / max(len(labels), 1)
            f = Finding(
                id=self.new_id(), kind="dns_nxdomain", category="fault", hosts=[client],
                time_start=n["first"], time_end=n["last"],
                wireshark_filter=f"ip.dst == {client} && dns.flags.rcode == 3",
                details={"client": client, "count": n["count"], "queries": total, "distinct_names": len(names),
                         "names": names[:15], "avg_entropy": round(avg_entropy, 2), "avg_label_len": round(avg_len, 1),
                         "rate": round(n["count"] / total, 2)},
            )
            f.add_evidence(n["frames"])
            findings.append(f)
        return findings

    @staticmethod
    def _window_queries(s: dict[str, Any], key: str) -> int:
        """Queries sent while this kind of failure was happening (rate is measured there)."""
        times = s.get(key) or []
        if not times:
            return max(s["queries"], 1)
        lo, hi = min(times) - 1.0, max(times) + 1.0
        return max(sum(1 for t in s["times"] if lo <= t <= hi), 1)

    def _finding(self, kind: str, server: str, s: dict[str, Any], failures: int, queries: int,
                 frames: list[int], wfilter: str) -> Finding:
        f = Finding(
            id=self.new_id(), kind=kind, category="fault", hosts=[server] + sorted(s["clients"])[:20],
            time_start=s["first"] or 0.0, time_end=s["last"] or 0.0, wireshark_filter=wfilter,
            details={"server": server, "failures": failures, "queries": queries,
                     "rate": round(failures / queries, 2), "clients": sorted(s["clients"])[:30],
                     "client_count": len(s["clients"]), "answered": s["answered"],
                     "servfail": s["servfail"], "refused": s["refused"], "timeouts": s["timeouts"]},
        )
        f.add_evidence(frames)
        return f
