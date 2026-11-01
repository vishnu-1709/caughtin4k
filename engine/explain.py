"""Plain-language text, likely causes, fix steps and benign alternatives. Template based, offline.

Wording rule: when the verdict is "uncertain", fixes start with checks, never with drastic action.
"""
from __future__ import annotations

from typing import Any, Callable

from .context import Context, ip_kind, vendor
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
    ip = ctx.gateway_ip if d["gateway_involved"] else ips[0]
    orig = d["original_macs"][ip]
    who_new, who_orig = _mac_label(new), _mac_label(orig)
    gw = d["gateway_involved"]
    target = "your router" if gw else f"the device at {ip}"
    by_ip = d.get("targets_by_ip", {})
    told = by_ip.get(ip) or d["targets"]
    victims = ", ".join(ctx.device_label(t) for t in told[:3]) or "devices on the network"
    also = [o for o in ips if o != ip]
    also_txt = ""
    if also:
        to = ", ".join(ctx.device_label(t) for t in by_ip.get(also[0], [])[:2]) or "other devices"
        also_txt = f" It also tells {to} that it is {', '.join(also)}, so both directions pass through it."
    tech_title_ip = ", ".join(ips)
    if f.verdict == "attack":
        return {
            "title_simple": f"Someone is pretending to be {target}",
            "title_technical": f"ARP spoofing of {tech_title_ip} by {new}",
            "explanation": (f"The device {who_new} keeps telling {victims} that it is {target}. "
                            f"Their traffic is then sent to it instead of the real owner ({who_orig}), "
                            "so it can read or change that traffic (a man-in-the-middle attack)." + also_txt),
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


PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "email (SMTP)", 53: "DNS", 80: "web (HTTP)",
              139: "Windows file sharing", 443: "secure web (HTTPS)", 445: "Windows file sharing (SMB)",
              631: "printing (IPP)", 3306: "MySQL database", 3389: "Remote Desktop", 8080: "web (alt)",
              9100: "printing"}


def _port(p: int) -> str:
    return f"port {p} ({PORT_NAMES[p]})" if p in PORT_NAMES else f"port {p}"


def _port_scan(f: Finding, ctx: Context) -> Texts:
    d = f.details
    scanner = ctx.device_label(d["scanner"])
    target = ctx.device_label(d["main_target"]) if d["main_target"] else "several devices"
    what = (f"{d['ports_tried']} different ports on {target}" if d["vertical"]
            else f"{d['target_count']} devices on the same port")
    open_txt = ", ".join(_port(p) for p in d["open_ports"][:5]) or "none"
    if f.verdict == "attack":
        title = f"{scanner} is scanning your network for open doors"
        cause = "Someone is running a port-scanning tool (such as Nmap) from this device to find services to attack."
        steps = [
            f"Identify the device {scanner} and who is using it.",
            "If nobody authorised a scan, disconnect it from the network and check it for malware or misuse.",
            f"Review the services it found open on the target ({open_txt}); turn off any you do not need.",
            "Keep the scanned device updated and protected by its firewall.",
        ]
    else:
        title = f"{scanner} is probing many ports: possibly a scan"
        cause = "Could be an unauthorised scan, or an IT/monitoring tool that checks services."
        steps = [
            f"Ask whether {scanner} runs an inventory, monitoring or security tool.",
            "If not, watch it closely and capture again; disconnect it if the probing continues.",
            f"Check that only needed services are open on the target ({open_txt}).",
        ]
    return {
        "title_simple": title,
        "title_technical": f"TCP {'SYN ' if d['half_open'] else ''}port scan from {d['scanner']} "
                           f"({d['ports_tried']} ports, {d['target_count']} hosts)",
        "explanation": (f"Within {d['duration']:.0f} seconds, {scanner} tried to connect to {what}. "
                        f"{d['closed'] + d['no_reply']} attempts were refused or ignored, which is what "
                        f"looking for open services looks like. Open services found: {open_txt}."),
        "explanation_technical": (f"{d['attempts']} SYNs, {d['rate']}/s; outcomes: {d['closed']} RST, "
                                  f"{d['no_reply']} no reply, {len(d['open_ports'])} open, {d['completed']} completed; "
                                  f"max {d['max_ports_one_host']} ports/host and {d['max_hosts_one_port']} hosts/port "
                                  f"in a {ctx.cfg['scan_window']:.0f}s window; half-open RSTs: {d['half_open']}."),
        "likely_cause": cause,
        "fix_steps": steps,
        "benign_alternative": ("Network inventory tools, printer/NAS discovery apps and IT security audits also "
                               "scan. Check whether someone authorised a scan from this device."),
    }


def _service_refused(f: Finding, ctx: Context) -> Texts:
    d = f.details
    server = ctx.device_label(d["server"])
    return {
        "title_simple": f"The service on {server} is not accepting connections",
        "title_technical": f"TCP RST to SYN from {d['server']}:{d['port']} ({d['client_count']} clients)",
        "explanation": (f"{d['client_count']} devices tried to reach {_port(d['port'])} on {server} and were turned "
                        "away immediately. The server is reachable, but the program that should answer on that "
                        "port is not running."),
        "explanation_technical": (f"{d['attempts']} SYNs to {d['server']}:{d['port']} answered with RST/ACK; "
                                  f"clients: {', '.join(d['clients'][:6])}."),
        "likely_cause": "The service crashed, was stopped, or was moved to a different port/server.",
        "fix_steps": [
            f"Log in to {server} and check that the service for {_port(d['port'])} is running; restart it.",
            "Check the service's logs for crash or configuration errors.",
            "If the service was moved on purpose, update the devices or shortcuts that still use the old address.",
        ],
        "benign_alternative": "This is a normal fault, not an attack: refusals come from the server itself.",
    }


def _connection_resets(f: Finding, ctx: Context) -> Texts:
    d = f.details
    sender = ctx.device_label(d["sender"])
    injected = f.verdict != "fault"
    return {
        "title_simple": (f"Connections with {sender} are being cut off" + (": resets may be forged" if injected else "")),
        "title_technical": f"{d['count']} mid-connection TCP RSTs from {d['sender']} (TTL {d['rst_ttl']} vs normal {d['normal_ttl']})",
        "explanation": (f"{d['count']} working connections with {sender} were suddenly closed with a 'reset'. "
                        "Users see downloads or pages break halfway."
                        + (" The resets don't look like they came from the real device." if injected else "")),
        "explanation_technical": (f"RSTs on established flows; peers: {', '.join(d['peers'][:6])}; "
                                  f"TTL of resets {d['rst_ttl']}, usual TTL {d['normal_ttl']}."),
        "likely_cause": ("A firewall/IPS or someone on the path injecting resets." if injected
                         else "The application or server is closing connections abruptly (crash, overload, timeout)."),
        "fix_steps": ([
            "Check whether a firewall or security appliance between the devices is set to block this traffic.",
            "If none is, treat it as possible tampering: capture at both ends and compare.",
            "Use encrypted connections (HTTPS/VPN) where possible.",
        ] if injected else [
            f"Check the logs of the application on {sender} around the times shown.",
            "Look for overload (CPU/memory) or idle-timeout settings on the server or firewall.",
            "Update or restart the application if it keeps crashing.",
        ]),
        "benign_alternative": "Firewalls closing idle sessions and app restarts also cause resets.",
    }


def _retrans(f: Finding, ctx: Context) -> Texts:
    d = f.details
    local = next((h for h in (d["a"], d["b"]) if ip_kind(h) == "private"), d["a"])
    remote = d["b"] if local == d["a"] else d["a"]
    a, b = ctx.device_label(local), ctx.device_label(remote)
    return {
        "title_simple": f"Packets are getting lost between {a} and {b}",
        "title_technical": f"TCP retransmissions {d['rate']:.0%} ({d['retransmissions']}/{d['data_segments']}) {d['a']} ↔ {d['b']}",
        "explanation": (f"{d['retransmissions']} of {d['data_segments']} data packets ({d['rate']:.0%}) had to be sent "
                        "again because the first copy never arrived. That makes downloads and video slow or stuttering."),
        "explanation_technical": (f"Exact (seq, len) repeats on {d['bad_flows']}/{d['flows']} flows; senders: "
                                  f"{', '.join(d['senders'])}; ports {d['ports']}; capture-wide rate {d['capture_rate']:.1%}."),
        "likely_cause": "A weak Wi-Fi signal, a faulty cable/port, or a link that is overloaded.",
        "fix_steps": [
            f"If {ctx.device_label(local)} is on Wi-Fi, move it closer to the access point or try a cable.",
            "Swap the network cable and switch port, and check the port for errors on the switch/router.",
            "Check whether the internet link is saturated (big downloads, backups) at that time.",
            "Restart the router if the loss affects many devices.",
        ],
        "benign_alternative": "Some loss is normal on busy Wi-Fi; it only matters at this rate.",
    }


def _dns_fail(f: Finding, ctx: Context) -> Texts:
    d = f.details
    server = ctx.device_label(d["server"])
    timeout = f.kind == "dns_timeout"
    return {
        "title_simple": (f"The DNS server {server} isn't answering" if timeout
                         else f"The DNS server {server} is failing to look up names"),
        "title_technical": (f"DNS timeouts at {d['server']}: {d['failures']}/{d['queries']} unanswered" if timeout
                            else f"DNS SERVFAIL/REFUSED at {d['server']}: {d['failures']}/{d['queries']}"),
        "explanation": (f"Devices ask {server} to turn website names into addresses. {d['failures']} of "
                        f"{d['queries']} questions ({d['rate']:.0%}) " +
                        ("got no reply, so websites seem 'down' even if the internet works."
                         if timeout else "came back as errors, so websites fail to open.")),
        "explanation_technical": (f"{d['timeouts']} timeouts (>{ctx.cfg['dns_timeout']:.0f}s), {d['servfail']} SERVFAIL, "
                                  f"{d['refused']} REFUSED; {d['client_count']} clients affected."),
        "likely_cause": ("The DNS server or its upstream internet connection is down or overloaded." if timeout
                         else "The DNS server cannot reach the upstream servers, or is misconfigured."),
        "fix_steps": [
            f"Restart the device acting as DNS server ({server}), often the router.",
            "Check that the router's internet connection works (try opening an IP address like 1.1.1.1).",
            "As a temporary fix, set a public DNS server (e.g. 1.1.1.1 or 9.9.9.9) in the router's DHCP settings.",
            "If it keeps happening, contact your internet provider.",
        ],
        "benign_alternative": "This is a plain fault: the server is not answering, nothing points to an attack.",
    }


def _nxdomain(f: Finding, ctx: Context) -> Texts:
    d = f.details
    client = ctx.device_label(d["client"])
    dga = f.verdict != "fault"
    return {
        "title_simple": (f"{client} keeps looking up random names that don't exist" if dga
                         else f"{client} keeps asking for website names that don't exist"),
        "title_technical": f"NXDOMAIN storm from {d['client']}: {d['count']}/{d['queries']} ({d['distinct_names']} names)",
        "explanation": (f"{d['count']} name lookups by {client} failed with 'no such name', for example "
                        f"{', '.join(d['names'][:3])}." +
                        (" The names look randomly generated, which some malware does." if dga
                         else " Usually a typo or an old address saved in a program.")),
        "explanation_technical": (f"Avg label entropy {d['avg_entropy']} bits/char, avg length {d['avg_label_len']}; "
                                  f"NXDOMAIN rate {d['rate']:.0%}."),
        "likely_cause": ("Possible malware using generated domain names (DGA) to find its control server." if dga
                         else "A mistyped or retired name in a program, bookmark or network setting."),
        "fix_steps": ([
            f"Run an up-to-date antivirus / malware scan on {client}.",
            "Check which program is making the lookups (Task Manager / Activity Monitor network tab).",
            "If malware is found, disconnect the device and change its passwords.",
        ] if dga else [
            f"Find which program on {client} uses {', '.join(d['names'][:2])} and correct the name.",
            "Check the device's DNS suffix / search domain settings.",
        ]),
        "benign_alternative": "Some security tools and browsers also look up random names to test DNS.",
    }


def _rogue_dhcp(f: Finding, ctx: Context) -> Texts:
    d = f.details
    rogue = ctx.device_label(d["rogue_ip"], d["rogue_mac"])
    attack = f.verdict == "attack"
    return {
        "title_simple": (f"A fake DHCP server at {d['rogue_ip']} is handing out bad network settings" if attack
                         else f"A second DHCP server at {d['rogue_ip']} is handing out network settings"),
        "title_technical": f"Rogue DHCP server {d['rogue']} ({d['rogue_mac']}) alongside {d['legit']}",
        "explanation": (f"When devices join the network, {rogue} answers them in addition to the normal server "
                        f"{d['legit']}. It tells them to use router {', '.join(d['rogue_router']) or '-'} and DNS "
                        f"{', '.join(d['rogue_dns']) or '-'} (normal: {', '.join(d['legit_router']) or '-'} / "
                        f"{', '.join(d['legit_dns']) or '-'}). Devices that accept it can be watched or redirected."),
        "explanation_technical": (f"{d['offers']} OFFER and {d['acks']} ACK from server-id {d['rogue']}; "
                                  f"clients: {', '.join(d['clients'][:5]) or 'none'}."),
        "likely_cause": ("An attacker's device running a DHCP server, or a home router plugged into the office "
                         "network by mistake."),
        "fix_steps": [
            f"Find and unplug the device {rogue} (MAC {d['rogue_mac']}).",
            "On affected devices, renew the address (Windows: `ipconfig /release` then `/renew`) and check that the "
            f"router shown is {', '.join(d['legit_router']) or 'the real router'}.",
            "Enable DHCP snooping on managed switches so only the real server's port may answer.",
        ] if attack else [
            f"Check whether {rogue} is a backup DHCP server you set up on purpose.",
            "If not, unplug it; two DHCP servers cause random address conflicts.",
        ],
        "benign_alternative": ("A spare home router or Wi-Fi extender with DHCP turned on causes the same picture. "
                               "It is still worth removing."),
    }


def _dns_hijack(f: Finding, ctx: Context) -> Texts:
    d = f.details
    server = ctx.device_label(d["server"])
    example = f"{d['private'][0][0]} → {d['private'][0][1]}" if d["private"] else ", ".join(d["domains"][:2])
    attack = f.verdict == "attack"
    return {
        "title_simple": (f"Websites are being redirected by a fake DNS server ({d['server']})" if attack
                         else f"Unexpected DNS answers from {d['server']}"),
        "title_technical": f"DNS hijack/spoofing by {d['server']} ({d['private_count']} private answers, "
                           f"{d['conflicts']} conflicts, {d['unasked']} unsolicited)",
        "explanation": (f"When devices ask where a website is, {server} gives the wrong address ({example}). "
                        "Typing the right name then opens the attacker's look-alike page, which can steal passwords."
                        if attack else
                        f"{server} returned unusual answers ({example}). This can be an attack or an internal "
                        "DNS setup."),
        "explanation_technical": (f"Domains: {', '.join(d['domains'][:5])}; clients: {', '.join(d['clients'][:5])}; "
                                  f"legit DHCP DNS: {', '.join(d['dhcp_legit_dns']) or 'unknown'}; "
                                  f"from rogue DHCP: {d['from_rogue_dhcp']}."),
        "likely_cause": ("A device on the network is posing as the DNS server (often set up through a rogue DHCP "
                         "server) to redirect traffic." if attack else
                         "Either DNS tampering or an internal DNS that answers public names locally."),
        "fix_steps": ([
            f"Do not enter passwords on affected devices ({', '.join(d['clients'][:3]) or 'see evidence'}) until fixed.",
            f"Unplug the device at {d['server']} and remove any rogue DHCP server (see the linked issue).",
            "On each affected device, renew its network settings and check its DNS server is the real one "
            f"({', '.join(d['dhcp_legit_dns']) or 'your router'}); clear the DNS cache (`ipconfig /flushdns`).",
            "Change any passwords typed while the redirect was active.",
        ] if attack else [
            f"Ask whoever manages DNS whether {', '.join(d['domains'][:2])} is meant to resolve internally.",
            "If not, treat it as tampering: find the device at that address and check affected devices' DNS settings.",
        ]),
        "benign_alternative": ("Companies sometimes point public names at internal servers on purpose "
                               "(split-horizon DNS), and captive portals redirect until you log in."),
    }


def _slow(f: Finding, ctx: Context) -> Texts:
    d = f.details
    dns = d["measure"] == "dns"
    server = ctx.device_label(d["server"]) if not d["network_wide"] else "many servers"
    return {
        "title_simple": ("Website names are slow to look up" if dns else
                         ("Everything on this network is slow to respond" if d["network_wide"]
                          else f"{server} is slow to respond")),
        "title_technical": (f"{'DNS response' if dns else 'TCP handshake'} delay at {d['server']}: "
                            f"median {d['slow_median_ms']} ms (capture median {d['median_ms']} ms)"),
        "explanation": (f"{d['slow']} times, {server} took about {d['slow_median_ms'] / 1000:.1f} s to answer "
                        f"(worst {d['worst_ms'] / 1000:.1f} s), while a normal answer here takes "
                        f"{d['median_ms']} ms. Users feel this as pages that hang before loading."),
        "explanation_technical": (f"{d['slow']}/{d['samples']} samples above {d['threshold_ms']} ms "
                                  f"(max(3× median, floor)); worst {d['worst_ms']} ms."),
        "likely_cause": ("The server is overloaded or far away, or the path to it is congested." if not dns
                         else "The DNS server or its upstream link is overloaded."),
        "fix_steps": [
            f"Check the load (CPU, memory, connections) on {server}." if not d["network_wide"]
            else "Check whether the internet link is saturated (speed test, router traffic graph).",
            "Compare with a capture at a quiet time to see whether the delay is constant or only at peak times.",
            "If it is an internet server you don't control, contact its owner or your provider; otherwise "
            "restart or scale the service.",
        ],
        "benign_alternative": "Servers on the other side of the world are naturally slower; it matters when it changes.",
    }


TEMPLATES: dict[str, Callable[[Finding, Context], Texts]] = {
    "arp_spoofing": _arp,
    "duplicate_ip": _arp,
    "ip_conflict": _arp,
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
