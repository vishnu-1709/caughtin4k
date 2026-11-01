"""The list of checks CaughtIn4K runs, and the per-capture status of each (shared by UI and report)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

SEVERITY = {"attack": 0, "uncertain": 1, "fault": 2}


@dataclass(frozen=True)
class Check:
    name: str
    category: str  # "attack" | "fault"
    blurb: str
    kinds: frozenset[str]
    needs: str | None  # protocol that must be present for the check to have anything to inspect


CHECKS: list[Check] = [
    Check("ARP spoofing", "attack", "a device pretending to be the router or another device",
          frozenset({"arp_spoofing", "ip_conflict"}), "ARP"),
    Check("Port scans", "attack", "a device probing others for open services", frozenset({"port_scan"}), "TCP"),
    Check("DNS hijacking", "attack", "fake answers that send websites to the wrong place",
          frozenset({"dns_hijack"}), "DNS"),
    Check("Rogue DHCP servers", "attack", "an unknown device handing out network settings",
          frozenset({"rogue_dhcp"}), "DHCP"),
    Check("Duplicate IPs / ARP conflicts", "fault", "two devices using the same address",
          frozenset({"duplicate_ip"}), "ARP"),
    Check("Packet loss (TCP retransmissions)", "fault", "data that had to be sent again",
          frozenset({"tcp_retransmissions"}), "TCP"),
    Check("Refused / reset connections", "fault", "services that are down or connections cut off",
          frozenset({"service_refused", "connection_resets"}), "TCP"),
    Check("DNS failures", "fault", "name lookups that time out or fail",
          frozenset({"dns_timeout", "dns_servfail", "dns_nxdomain"}), "DNS"),
    Check("Unusual delays", "fault", "servers or DNS that answer far slower than normal",
          frozenset({"slow_responses", "slow_dns"}), None),
    Check("MTU mismatches", "fault", "packets too big for part of the path",
          frozenset({"mtu_mismatch", "mtu_offload"}), None),
    Check("Passwords sent unencrypted", "fault", "logins over FTP, POP3, IMAP, SMTP or plain HTTP",
          frozenset({"cleartext_credentials"}), "TCP"),
]


def check_status(result: Any) -> list[dict[str, Any]]:
    """For each check: status 'found' | 'clear' | 'no_data', plus the worst verdict found."""
    rows = []
    for c in CHECKS:
        hits = [f for f in result.findings if f.kind in c.kinds]
        if hits:
            worst = min(hits, key=lambda f: SEVERITY.get(f.verdict, 3)).verdict
            status = "found"
        elif c.needs and not result.protocols.get(c.needs):
            worst, status = "", "no_data"
        else:
            worst, status = "", "clear"
        rows.append({"name": c.name, "category": c.category, "blurb": c.blurb, "status": status,
                     "verdict": worst, "count": len(hits)})
    return rows
