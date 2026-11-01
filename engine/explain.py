"""Plain-language text, likely causes, fix steps and benign alternatives. Template based, offline.

Wording rule: when the verdict is "uncertain", fixes start with checks, never with drastic action.
"""
from __future__ import annotations

from typing import Any, Callable

from .context import Context, vendor
from .findings import Finding

Texts = dict[str, Any]


def _mac_label(mac: str) -> str:
    v = vendor(mac)
    return f"{mac} ({v})" if v != "Unknown" else mac


def _ago(f: Finding, ctx: Context) -> str:
    start = (f.time_start - (ctx.start or f.time_start))
    return f"{start:.0f}s"


# ------------------------------------------------------------------ ARP family
def _arp(f: Finding, ctx: Context) -> Texts:
    d = f.details
    ips, new = d["ips"], d["new_mac"]
    ip = ips[0]
    orig = d["original_macs"][ip]
    who_new, who_orig = _mac_label(new), _mac_label(orig)
    gw = d["gateway_involved"]
    target = "your router" if gw else f"the device at {ip}"
    victims = ", ".join(ctx.device_label(t) for t in d["targets"][:3]) or "devices on the network"
    tech_title_ip = ", ".join(ips)
    if f.verdict == "attack":
        return {
            "title_simple": f"Someone is pretending to be {target}",
            "title_technical": f"ARP spoofing of {tech_title_ip} by {new}",
            "explanation": (f"The device {who_new} keeps telling {victims} that it is {target}. "
                            f"Their traffic is then sent to it instead of the real owner ({who_orig}), "
                            "so it can read or change that traffic (a man-in-the-middle attack)."),
            "explanation_technical": (f"{d['claims']} ARP messages from {new} claim {tech_title_ip} "
                                      f"({d['unsolicited']} unsolicited replies, ~{d['rate_per_min']:.0f}/min, "
                                      f"{d['flips']} IP→MAC flips). Original owner: {orig}. Targets: "
                                      f"{', '.join(d['targets'][:5]) or 'n/a'}."),
            "likely_cause": f"A device ({who_new}) is running an ARP-spoofing tool to intercept traffic.",
            "fix_steps": [
                f"Find the device with MAC {new}: check your router's list of connected devices "
                f"(it uses IP {', '.join(d['own_ips']) or 'unknown'}) and the switch port it is on.",
                "Disconnect it from the network (unplug it or block its MAC on the router / Wi-Fi).",
                f"On affected computers, clear the ARP cache (Windows: `arp -d *`, Linux: `ip neigh flush all`).",
                "Change passwords that were used while the attack was running; prefer HTTPS-only sites.",
                "If your switch supports it, turn on Dynamic ARP Inspection or port security to prevent repeats.",
            ],
            "benign_alternative": ("Rarely, this is a router failover (a backup router taking over) or a "
                                   "network appliance using proxy ARP. Check whether "
                                   f"{new} belongs to equipment you own and configured for that."),
        }
    if f.verdict == "fault":
        return {
            "title_simple": f"Two devices are using the same address {ip}",
            "title_technical": f"Duplicate IP address {ip} ({orig} and {new})",
            "explanation": (f"Both {who_orig} and {who_new} are set up to use {ip}. "
                            "The network can only deliver traffic for one address to one device, so "
                            "both will see random drop-outs and failed connections."),
            "explanation_technical": (f"{ip} is claimed by {orig} and {new} ({d['claims']} ARP messages from the "
                                      f"newcomer, {d['replies']} replies, {d['unsolicited']} unsolicited, "
                                      f"{d['dad_conflicts']} ARP-probe conflicts). Both MACs source IP traffic "
                                      f"from {ip}: {d['both_send_traffic']}."),
            "likely_cause": ("One device has a manually set (static) IP that is also handed out by the router's "
                             "DHCP, or two devices were given the same static IP."),
            "fix_steps": [
                f"Find both devices: {who_orig} and {who_new} (check the router's device list).",
                f"On the device that should not have {ip}, switch its network setting to 'Obtain an IP "
                "address automatically' (DHCP), or give it a free address.",
                f"If {ip} must stay static, reserve it in the router's DHCP settings or move it outside the "
                "DHCP range.",
                "Reconnect both devices and check that the warning no longer appears.",
            ],
            "benign_alternative": "This is already the harmless explanation: a configuration mistake, not an attack.",
        }
    return {
        "title_simple": f"Two devices claim the address {ip}: cause unclear",
        "title_technical": f"IP→MAC conflict for {tech_title_ip} ({orig} vs {new})",
        "explanation": (f"{who_new} has started answering for {ip}, which earlier belonged to {who_orig}. "
                        "The evidence is mixed: this could be a replaced or failed-over device, or someone "
                        "impersonating it."),
        "explanation_technical": (f"{d['claims']} ARP claims from {new} for {tech_title_ip}; "
                                  f"{d['unsolicited']}/{d['replies']} replies unsolicited; "
                                  f"attack score {d.get('score_attack')} vs harmless {d.get('score_harmless')}."),
        "likely_cause": "Either a device was replaced or reconfigured, or a device is impersonating it.",
        "fix_steps": [
            f"Check whether {new} is equipment you own (router list, sticker on the device, vendor "
            f"{vendor(new)}).",
            "Ask whether anyone replaced the router or a device, or changed IP settings, around the time shown.",
            "If nobody did: treat it as suspicious, disconnect that device and clear ARP caches.",
            "If it was planned: no action needed; the old entry will age out.",
        ],
        "benign_alternative": (f"A router or device replacement, or a backup router taking over, also makes "
                               f"{ip} move to a new MAC. Check if anything was changed at that time."),
    }


TEMPLATES: dict[str, Callable[[Finding, Context], Texts]] = {
    "arp_spoofing": _arp,
    "duplicate_ip": _arp,
    "ip_conflict": _arp,
}


def explain_all(findings: list[Finding], ctx: Context) -> None:
    """Fill the text fields of every finding from its template."""
    for f in findings:
        fn = TEMPLATES.get(f.kind)
        if fn is None:
            f.title_simple = f.title_simple or f.kind.replace("_", " ").capitalize()
            f.title_technical = f.title_technical or f.title_simple
            continue
        for key, value in fn(f, ctx).items():
            setattr(f, key, value)
