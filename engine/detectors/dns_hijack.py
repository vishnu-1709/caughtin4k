"""DNS hijacking: forged/unexpected answers, conflicting answers, public names pointing into the LAN."""
from __future__ import annotations

from collections import Counter
from typing import Any

from ..context import Context, ip_kind
from ..findings import Finding
from ..loader import PacketView
from .base import Detector
from .rogue_dhcp import legit_dhcp_server

MAX_QUERIES = 20_000
PUBLIC_TLDS = {"com", "net", "org", "io", "in", "edu", "gov", "co", "uk", "de", "info", "app", "dev", "ai", "me",
               "us", "ac", "xyz", "cloud", "tv", "biz"}
INTERNAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".intranet", ".corp", ".localdomain", ".home.arpa",
                     ".in-addr.arpa", ".private", ".test", ".invalid", ".localhost")


def looks_public(name: str) -> bool:
    """A name that should resolve on the internet (not an internal/split-horizon name)."""
    if not name or "." not in name or name.endswith(INTERNAL_SUFFIXES):
        return False
    return name.rsplit(".", 1)[-1] in PUBLIC_TLDS


class DnsHijackDetector(Detector):
    name = "dns_hijack"

    def __init__(self) -> None:
        super().__init__()
        self.queries: dict[tuple[str, int, str], dict[str, Any]] = {}
        self.servers: dict[str, dict[str, Any]] = {}  # answering server -> evidence

    def _server(self, ip: str) -> dict[str, Any] | None:
        if ip not in self.servers and len(self.servers) >= 1000:
            return None
        return self.servers.setdefault(ip, {"answers": 0, "unasked": 0, "conflicts": 0, "private": [],
                                            "self_answers": 0, "clients": set(), "frames": [],
                                            "first": None, "last": None, "domains": set(),
                                            "clean_macs": Counter(), "bad_macs": Counter()})

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        d = pkt.dns
        if not d or not d["qname"]:
            return
        if not d["qr"]:
            key = (pkt.ip_src, d["id"], d["qname"])
            q = self.queries.get(key)
            if q is None and len(self.queries) < MAX_QUERIES:
                q = self.queries[key] = {"servers": set(), "answers": {}, "frame": frame_no}
            if q is not None:
                q["servers"].add(pkt.ip_dst)
            return
        s = self._server(pkt.ip_src)
        if s is None:
            return
        s["answers"] += 1
        key = (pkt.ip_dst, d["id"], d["qname"])
        q = self.queries.get(key)
        a_records = frozenset(a[2] for a in d["answers"] if a[1] == 1)
        suspicious = False
        if q is not None:
            if pkt.ip_src not in q["servers"]:
                s["unasked"] += 1  # answer from a server the client never asked
                suspicious = True
            for other_server, other in q["answers"].items():
                if a_records and other and other != a_records:
                    s["conflicts"] += 1  # same question, different answer
                    suspicious = True
                    other_s = self.servers.get(other_server)
                    if other_s is not None:
                        other_s["conflicts"] += 1
            q["answers"][pkt.ip_src] = a_records
        if looks_public(d["qname"]):
            for ip in a_records:
                if ip_kind(ip) in ("private", "special"):
                    if len(s["private"]) < 50:
                        s["private"].append((d["qname"], ip))
                    s["self_answers"] += int(ip == pkt.ip_src)
                    suspicious = True
        if pkt.eth_src:
            bucket = s["bad_macs"] if (suspicious or any(ip_kind(ip) == "private" for ip in a_records)
                                       and looks_public(d["qname"])) else s["clean_macs"]
            if pkt.eth_src in bucket or len(bucket) < 16:
                bucket[pkt.eth_src] += 1
        if suspicious:
            if len(s["clients"]) < 200:
                s["clients"].add(pkt.ip_dst)
            if len(s["domains"]) < 100:
                s["domains"].add(d["qname"])
            s["first"] = ts if s["first"] is None else s["first"]
            s["last"] = ts
            if len(s["frames"]) < 100:
                s["frames"].append(frame_no)
                if q is not None:
                    s["frames"].append(q["frame"])
                ctx.remember(pkt)

    def finish(self, ctx: Context) -> list[Finding]:
        legit_id = legit_dhcp_server(ctx)
        legit_dns = set(ctx.dhcp_servers[legit_id]["dns"]) if legit_id else set()
        rogue_dns = {s for sid, e in ctx.dhcp_servers.items() if sid != legit_id for s in e["dns"]} - legit_dns
        main_dns = ctx.dns_servers.most_common(1)[0][0] if ctx.dns_servers else None
        findings = []
        for server, s in self.servers.items():
            if not (s["unasked"] or s["conflicts"] or s["private"]):
                continue
            # the frames list holds both responses and their queries; make sure query rows exist
            usual = s["clean_macs"].most_common(1)[0][0] if s["clean_macs"] else None
            forged = sorted(m for m in s["bad_macs"] if usual and m != usual)
            f = Finding(
                id=self.new_id(), kind="dns_hijack", category="attack",
                hosts=[server] + sorted(s["clients"])[:20] + forged,
                time_start=s["first"] or ctx.start or 0.0, time_end=s["last"] or ctx.end or 0.0,
                wireshark_filter=f"dns.flags.response == 1 && ip.src == {server}",
                details={
                    "server": server, "answers": s["answers"], "unasked": s["unasked"],
                    "conflicts": s["conflicts"], "private": s["private"][:10],
                    "private_count": len(s["private"]), "self_answers": s["self_answers"],
                    "domains": sorted(s["domains"])[:10], "clients": sorted(s["clients"])[:20],
                    "from_rogue_dhcp": server in rogue_dns, "dhcp_legit_dns": sorted(legit_dns),
                    "is_main_dns": server == main_dns and server in legit_dns | ({main_dns} if not legit_dns else set()),
                    "server_is_local": ip_kind(server) == "private",
                    "forged_macs": forged, "usual_mac": usual,
                },
            )
            f.add_evidence(s["frames"])
            findings.append(f)
        return findings
