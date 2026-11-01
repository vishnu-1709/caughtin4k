"""Group findings into incidents (time overlap + shared hosts) and apply exactly two causal rules."""
from __future__ import annotations

from .context import Context
from .findings import Finding, Incident

SEVERITY = {"attack": 0, "uncertain": 1, "fault": 2}
TOLERANCE = 5.0  # seconds of slack when checking time overlap
SLOWDOWN_KINDS = {"tcp_retransmissions", "slow_responses"}


def _overlap(a: Finding, b: Finding) -> bool:
    return a.time_start - TOLERANCE <= b.time_end and b.time_start - TOLERANCE <= a.time_end


def _causal_links(findings: list[Finding]) -> list[tuple[Finding, Finding, str, str]]:
    """(cause, effect, text on cause, text on effect) for the two supported rules."""
    links = []
    for cause in findings:
        if cause.kind == "rogue_dhcp":
            rogue_dns = set(cause.details.get("rogue_dns", []))
            for eff in findings:
                if eff.kind == "dns_hijack" and eff.details.get("server") in rogue_dns:
                    links.append((cause, eff,
                                  f"Caused: fake DNS answers from {eff.details['server']} (the DNS server it hands out).",
                                  f"Caused by: the rogue DHCP server {cause.details['rogue']} told devices to use "
                                  f"{eff.details['server']} as their DNS server."))
        if cause.kind == "arp_spoofing":
            victims = set(cause.details.get("ips", [])) | set(cause.details.get("targets", []))
            for eff in findings:
                if eff.kind in SLOWDOWN_KINDS and victims & set(eff.hosts) and _overlap(cause, eff):
                    who = ", ".join(sorted(victims & set(eff.hosts)))
                    links.append((cause, eff,
                                  f"Likely caused: the slowdown/packet loss for {who} (its traffic detours "
                                  "through the impostor).",
                                  f"Likely caused by: the ARP spoofing attack. {who}'s traffic is being "
                                  f"detoured through {cause.details.get('new_mac')}."))
    return links


def group(findings: list[Finding], ctx: Context) -> list[Incident]:
    """Union-find over findings; returns incidents sorted by severity."""
    parent = {f.id: f.id for f in findings}

    def root(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        parent[root(a)] = root(b)

    ignore = {ctx.gateway_ip, ctx.gateway_mac, None, "?"}
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            same_subject = bool(a.hosts and b.hosts and a.hosts[0] == b.hosts[0])  # e.g. two problems of one server
            if _overlap(a, b) and ((set(a.hosts) & set(b.hosts)) - ignore or same_subject):
                union(a.id, b.id)

    links = _causal_links(findings)
    caused_by: dict[str, str] = {}
    for cause, eff, cause_text, eff_text in links:
        union(cause.id, eff.id)
        if cause_text not in cause.linked_text:
            cause.linked_text = (cause.linked_text + " " + cause_text).strip()
        eff.linked_text = eff_text
        caused_by[root(eff.id)] = f"{cause.title_simple} → {eff.title_simple}"

    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(root(f.id), []).append(f)
    incidents = []
    for n, (rid, members) in enumerate(sorted(groups.items(), key=lambda kv: min(SEVERITY.get(f.verdict, 3) for f in kv[1])), 1):
        members.sort(key=lambda f: SEVERITY.get(f.verdict, 3))
        lead = members[0]
        inc_id = f"incident-{n}"
        for f in members:
            f.incident_id = inc_id
        summary = lead.title_simple if len(members) == 1 else (
            f"{lead.title_simple} (+{len(members) - 1} related issue{'s' if len(members) > 2 else ''})")
        link = next((v for k, v in caused_by.items() if root(k) == rid), "")
        incidents.append(Incident(
            id=inc_id, finding_ids=[f.id for f in members], verdict=lead.verdict, summary=summary,
            caused_by=link, hosts=sorted({h for f in members for h in f.hosts})[:30],
            time_start=min(f.time_start for f in members), time_end=max(f.time_end for f in members)))
    return incidents
