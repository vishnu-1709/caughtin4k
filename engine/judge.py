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


JUDGES: dict[str, JudgeFn] = {
    "ip_conflict": _ip_conflict,
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
