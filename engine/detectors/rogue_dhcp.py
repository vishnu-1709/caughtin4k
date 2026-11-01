"""Rogue DHCP: more than one DHCP server answering, possibly handing out different router/DNS."""
from __future__ import annotations

from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import PacketView
from .base import Detector


def _top(counter: Any) -> list[str]:
    return [k for k, _ in counter.most_common(3)]


def legit_dhcp_server(ctx: Context) -> str | None:
    """The server most likely to be the real one: it is the gateway or hands out the real gateway,
    otherwise the busiest/earliest."""
    servers = ctx.dhcp_servers
    if not servers:
        return None

    def score(sid: str) -> tuple:
        e = servers[sid]
        is_gw = int(ctx.gateway_mac is not None and e["mac"] == ctx.gateway_mac)
        gives_gw = int(ctx.gateway_ip in e["routers"])
        return (-is_gw, -gives_gw, -(e["acks"] + e["offers"]), e["first_ts"])

    return min(servers, key=score)


class RogueDhcpDetector(Detector):
    name = "rogue_dhcp"

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        return  # the shared Context already records every DHCP OFFER/ACK

    def finish(self, ctx: Context) -> list[Finding]:
        if len(ctx.dhcp_servers) < 2:
            return []
        legit_id = legit_dhcp_server(ctx)
        legit = ctx.dhcp_servers[legit_id]
        findings = []
        for sid, e in ctx.dhcp_servers.items():
            if sid == legit_id:
                continue
            routers, dns = _top(e["routers"]), _top(e["dns"])
            f = Finding(
                id=self.new_id(), kind="rogue_dhcp", category="attack",
                hosts=[sid, e["mac"] or "?", legit_id] + sorted(e["clients"])[:10],
                time_start=e["first_ts"], time_end=e["last_ts"],
                wireshark_filter=f"dhcp.option.dhcp_server_id == {sid} || dhcp.option.dhcp_server_id == {legit_id}",
                details={
                    "rogue": sid, "rogue_ip": e["ip"], "rogue_mac": e["mac"], "legit": legit_id,
                    "legit_mac": legit["mac"], "rogue_router": routers, "rogue_dns": dns,
                    "legit_router": _top(legit["routers"]), "legit_dns": _top(legit["dns"]),
                    "offers": e["offers"], "acks": e["acks"], "clients": sorted(e["clients"])[:20],
                    "client_count": len(e["clients"]), "rogue_first": e["first_ts"],
                    "legit_first": legit["first_ts"],
                },
            )
            f.add_evidence(e["frames"] + legit["frames"][:20])
            findings.append(f)
        return findings
