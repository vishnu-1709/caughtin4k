"""Fault vs attack judge: explicit, weighted indicators on both sides, per finding kind.

Each rule returns (weight, text). The verdict comes from comparing the two totals:
  attack    - attack evidence is strong AND clearly outweighs the harmless explanation
  fault     - the harmless explanation clearly wins
  uncertain - mixed evidence (a real, honest outcome)
"""
from __future__ import annotations

from typing import Callable

from .context import Context
from .findings import Finding

Indicators = list[tuple[int, str]]
JudgeFn = Callable[[Finding, Context], tuple[Indicators, Indicators]]

ATTACK_MIN = 4  # minimum attack score before we ever say "attack"
MARGIN = 3  # attack score must beat the harmless score by this much
RENAME = {  # final kind depends on the verdict for shared-logic detectors
    "ip_conflict": {"attack": "arp_spoofing", "fault": "duplicate_ip", "uncertain": "ip_conflict"},
}


def _ip_conflict(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    cfg = ctx.cfg
    pro: Indicators = []
    con: Indicators = []
    if d["gateway_involved"]:
        pro.append((3, f"The address being claimed belongs to the router ({ctx.gateway_ip}); "
                       "whoever owns it sees everyone's internet traffic."))
    if d["unsolicited"] >= cfg["arp_spoof_min_unsolicited"]:
        pro.append((2, f"{d['unsolicited']} ARP replies were sent without anyone asking (unsolicited)."))
    if d["rate_per_min"] >= cfg["arp_high_rate_per_min"] and d["claims"] >= 10:
        pro.append((1, f"The claim was repeated about {d['rate_per_min']:.0f} times a minute, "
                       "as if to keep caches poisoned."))
    if d["own_ips"]:
        pro.append((2, f"The same device ({d['new_mac']}) also uses its own address "
                       f"{', '.join(d['own_ips'][:3])}: one device is answering for several addresses."))
    if len(d["ips"]) > 1:
        pro.append((1, f"It claims {len(d['ips'])} addresses that belong to other devices."))
    if d["flips"] >= 6:
        pro.append((1, f"The owner of the address switched back and forth {d['flips']} times."))
    if d["eth_mismatch"]:
        pro.append((1, "The sender MAC inside the ARP message differs from the Ethernet sender (hand-crafted packets)."))

    if d["replies"] and d["unsolicited"] / max(d["replies"], 1) < 0.2:
        con.append((2, "The ARP replies were answers to real requests, not unprompted."))
    if d["claims"] <= 6:
        con.append((1, f"Only {d['claims']} ARP messages from the newcomer: sporadic, not a flood."))
    if d["both_send_traffic"]:
        con.append((2, "Both devices send their own normal traffic from this address, like two machines "
                       "that were given the same IP."))
    if d["dad_conflicts"]:
        con.append((1, "A device checked whether the address was free and was told it was taken: "
                       "typical of a configuration clash."))
    if d["failover_mac"]:
        con.append((3, "A MAC address used by router-redundancy protocols (VRRP/HSRP) is involved: "
                       "this is often planned failover."))
    if not d["own_ips"] and not d["gateway_involved"]:
        con.append((1, "The newcomer does not use any other address."))
    return pro, con


COMMON_SERVICE_PORTS = {21, 22, 23, 25, 53, 80, 110, 123, 139, 143, 161, 389, 443, 445, 515, 631, 993, 995,
                        3306, 3389, 5900, 8080, 8443, 9100}


def _infra(ip: str, ctx: Context) -> bool:
    return bool(ctx.roles(ip))


def _port_scan(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    pro: Indicators = []
    con: Indicators = []
    if d["ports_tried"] >= 100:
        pro.append((3, f"Tried {d['ports_tried']} different ports in {d['duration']:.0f} s."))
    elif d["vertical"]:
        pro.append((2, f"Tried {d['max_ports_one_host']} different ports on {d['main_target']} within a minute."))
    if d["horizontal"]:
        pro.append((2, f"Contacted {d['max_hosts_one_port']} different devices on the same port within a minute (a sweep)."))
    if d["failure_ratio"] >= 0.8:
        pro.append((2, f"{d['failure_ratio']:.0%} of attempts were refused or got no answer: it is probing, not using services."))
    if d["rate"] >= 10:
        pro.append((1, f"{d['rate']:.0f} attempts per second, far faster than any person."))
    if d["half_open"] >= 3:
        pro.append((1, f"It hung up {d['half_open']} times right after a port answered (half-open 'SYN scan' pattern)."))
    if d["sequential_ratio"] >= 0.5 and d["ports_tried"] >= 20:
        pro.append((1, "Ports were tried in order (1, 2, 3...), like a scanning tool."))
    if _infra(d["scanner"], ctx):
        con.append((1, f"The source is network infrastructure ({', '.join(ctx.roles(d['scanner']))})."))
    if d["completion"] >= 0.15:
        con.append((1, f"{d['completion']:.0%} of attempts became real conversations."))
    if d["rate"] < 0.5:
        con.append((1, "Attempts are slow and spread out, like a monitoring or inventory tool."))
    if d["ports_tried"] < 40 and set(d["sample_ports"]) <= COMMON_SERVICE_PORTS:
        con.append((1, "Only common service ports were checked, as network-discovery tools (printers, NAS apps) do."))
    return pro, con


def _service_refused(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    con: Indicators = [
        (2, f"{d['client_count']} different devices were refused by the same server and port: the service is "
            "not running, it is not one client misbehaving."),
        (1, "Refusals are immediate replies from the server itself, which is what a stopped service does."),
    ]
    return [], con


def _connection_resets(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    pro: Indicators = []
    con: Indicators = []
    if d["normal_ttl"] is not None and d["ttl_jump"] >= ctx.cfg["rst_ttl_jump"]:
        pro.append((3, f"The resets arrive with a hop count (TTL {d['rst_ttl']}) different from the sender's normal "
                       f"packets (TTL {d['normal_ttl']}): they may be forged by a third party."))
    elif d["normal_ttl"] is not None:
        con.append((2, f"The resets have the same hop count (TTL {d['rst_ttl']}) as the sender's normal packets: "
                       "they really come from it."))
    con.append((1, "Applications, crashes and firewalls closing idle sessions commonly reset connections."))
    return pro, con


def _retrans(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    con: Indicators = [(2, f"{d['retransmissions']} of {d['data_segments']} data packets ({d['rate']:.0%}) had to be "
                          "sent again: classic packet loss on a weak or overloaded link.")]
    if d["bad_flows"] > 1:
        con.append((1, f"Loss affects {d['bad_flows']} separate connections, so it is the path, not one app."))
    if d["ack_gaps"] >= 5:
        con.append((1, "The capture itself also missed packets, so part of this may be recording loss."))
    return [], con


def _dns_fail(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    what = "went unanswered" if f.kind == "dns_timeout" else "were refused or failed"
    con: Indicators = [(2, f"{d['failures']} of {d['queries']} DNS questions to {d['server']} {what}.")]
    if d["client_count"] > 1:
        con.append((1, f"{d['client_count']} devices are affected, pointing at the server or its internet link."))
    return [], con


def _nxdomain(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    pro: Indicators = []
    con: Indicators = []
    random_names = d["avg_entropy"] >= 3.3 and d["avg_label_len"] >= 10
    if random_names and d["distinct_names"] >= 10:
        pro.append((3, f"{d['distinct_names']} different random-looking names were looked up (e.g. "
                       f"{', '.join(d['names'][:2])}): malware uses such generated names to find its server."))
    if d["distinct_names"] <= 3:
        con.append((2, f"The same {d['distinct_names']} name(s) keep failing: looks like a typo or an old setting."))
    if not random_names:
        con.append((2, "The names look human-made, not randomly generated."))
    return pro, con


def _rogue_dhcp(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    pro: Indicators = []
    con: Indicators = []
    same_router = set(d["rogue_router"]) == set(d["legit_router"])
    same_dns = set(d["rogue_dns"]) == set(d["legit_dns"])
    if not same_router:
        pro.append((2, f"It tells devices to use {', '.join(d['rogue_router']) or 'no'} as their router instead of "
                       f"{', '.join(d['legit_router']) or 'the normal one'}."))
    if d["rogue_ip"] in d["rogue_router"]:
        pro.append((2, "It names itself as the router, so new devices send all their traffic through it."))
    if not same_dns:
        pro.append((2, f"It hands out a different DNS server ({', '.join(d['rogue_dns']) or 'none'}), which can "
                       "redirect websites."))
    if d["rogue_ip"] in d["rogue_dns"]:
        pro.append((1, "It names itself as the DNS server."))
    if d["acks"] and d["client_count"]:
        pro.append((1, f"{d['client_count']} device(s) accepted its settings."))
    if same_router and same_dns:
        con.append((3, "It hands out exactly the same router and DNS as the main server, like a backup DHCP server."))
    if d["rogue_mac"] and d["rogue_mac"] == d["legit_mac"]:
        con.append((2, "Both servers are the same physical device (same MAC)."))
    if not d["acks"]:
        con.append((1, "No device accepted its offers."))
    return pro, con


def _dns_hijack(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    pro: Indicators = []
    con: Indicators = []
    if d["from_rogue_dhcp"]:
        pro.append((3, f"This DNS server ({d['server']}) was handed out only by a rogue DHCP server, not by the "
                       "network's real one."))
    if d["private_count"]:
        name, ip = d["private"][0]
        pro.append((2, f"Public website names were answered with local/private addresses (e.g. {name} → {ip}): "
                       "visitors are sent to a device on your own network."))
    if d["self_answers"]:
        pro.append((2, "The DNS server answered with its own address, sending visitors to itself."))
    if d["conflicts"]:
        pro.append((3, f"{d['conflicts']} question(s) received two different answers: one of them is forged."))
    if d["unasked"]:
        pro.append((2, f"{d['unasked']} answer(s) came from a server the device never asked (spoofed replies)."))
    if d["is_main_dns"] and not d["from_rogue_dhcp"]:
        con.append((2, "It is the network's normal DNS server, which may deliberately answer some names "
                       "with internal addresses (split-horizon DNS)."))
    if d["private_count"] and len(d["domains"]) == 1 and not (d["conflicts"] or d["unasked"]):
        con.append((1, "Only one name is affected."))
    return pro, con


def _slow(f: Finding, ctx: Context) -> tuple[Indicators, Indicators]:
    d = f.details
    what = "DNS answers" if d["measure"] == "dns" else "connection set-ups"
    con: Indicators = [(2, f"{d['slow']} of {d['samples']} {what} took longer than {d['threshold_ms']} ms "
                          f"(typical in this capture: {d['median_ms']} ms).")]
    if not d["network_wide"]:
        con.append((1, "Other servers in the same capture answer quickly, so the delay is at this server or its path."))
    return [], con


JUDGES: dict[str, JudgeFn] = {
    "ip_conflict": _ip_conflict,
    "port_scan": _port_scan,
    "service_refused": _service_refused,
    "connection_resets": _connection_resets,
    "tcp_retransmissions": _retrans,
    "dns_timeout": _dns_fail,
    "dns_servfail": _dns_fail,
    "dns_nxdomain": _nxdomain,
    "rogue_dhcp": _rogue_dhcp,
    "dns_hijack": _dns_hijack,
    "slow_responses": _slow,
    "slow_dns": _slow,
}


def _decide(pro: Indicators, con: Indicators, category: str) -> tuple[str, str]:
    p, c = sum(w for w, _ in pro), sum(w for w, _ in con)
    if p >= ATTACK_MIN and p >= c + MARGIN:
        margin = p - c
        return "attack", "high" if margin >= 6 else "medium" if margin >= 4 else "low"
    if c >= p + 2 and p < 3:
        margin = c - p
        return "fault", "high" if margin >= 4 else "medium" if margin >= 2 else "low"
    if category == "fault" and p == 0:
        return "fault", "medium" if c else "low"
    return "uncertain", "low"


def judge_all(findings: list[Finding], ctx: Context) -> None:
    """Set verdict, confidence, kind and both indicator lists on every finding."""
    for f in findings:
        fn = JUDGES.get(f.kind)
        if fn is None:
            f.verdict, f.confidence = f.category, "medium"
            continue
        pro, con = fn(f, ctx)
        f.indicators_for = [t for _, t in sorted(pro, key=lambda x: -x[0])]
        f.indicators_against = [t for _, t in sorted(con, key=lambda x: -x[0])]
        f.details["score_attack"] = sum(w for w, _ in pro)
        f.details["score_harmless"] = sum(w for w, _ in con)
        f.verdict, f.confidence = _decide(pro, con, f.category)
        f.kind = RENAME.get(f.kind, {}).get(f.verdict, f.kind)
