"""Shared network picture built during the single pass: devices, roles, baselines, capture quality."""
from __future__ import annotations

import ipaddress
from collections import Counter
from functools import lru_cache
from typing import Any

from scapy.config import conf

from .loader import ACK, FIN, RST, SYN, PacketView, flags_text

BROADCAST_MACS = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


@lru_cache(maxsize=65536)
def ip_kind(ip: str) -> str:
    """'private' (LAN), 'public', or 'special' (multicast, broadcast, unspecified, loopback...)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "special"
    if addr.is_multicast or addr.is_unspecified or addr.is_loopback or addr.is_link_local:
        return "special"
    if addr.version == 4 and (str(addr).endswith(".255") or str(addr) == "255.255.255.255"):
        return "special"
    if addr.is_private:
        return "private"
    if addr.is_reserved:
        return "special"
    return "public"


@lru_cache(maxsize=4096)
def vendor(mac: str) -> str:
    """Vendor name from Scapy's built-in OUI database, or 'Unknown'."""
    try:
        if int(mac.split(":")[0], 16) & 0x02:
            return "Randomised / locally set MAC"
        name = conf.manufdb._get_manuf(mac) if conf.manufdb else mac
    except Exception:
        return "Unknown"
    if not name or name == mac or ":" in name:
        return "Unknown"
    return name.replace(" Co.,Ltd.", "").replace(", Inc.", "").replace(" Inc.", "").strip()


def is_unicast_mac(mac: str | None) -> bool:
    if not mac or mac in BROADCAST_MACS:
        return False
    try:
        return not int(mac.split(":")[0], 16) & 0x01
    except ValueError:
        return False


class Context:
    """State shared by all detectors. Every collection is capped."""

    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.start: float | None = None
        self.end: float | None = None
        self.packets = 0
        self.bytes = 0
        self.protocols: Counter[str] = Counter()
        self.talkers: Counter[str] = Counter()
        self.links: Counter[str] = Counter()
        # devices
        self.ip_macs: dict[str, Counter[str]] = {}  # local IP -> MACs seen sending it (IP or ARP)
        self.ip_traffic_macs: dict[str, Counter[str]] = {}  # local IP -> MACs seen sending IP traffic with it
        self.mac_pkts: Counter[str] = Counter()
        self.mac_public: dict[str, set[str]] = {}  # MAC -> public IPs it delivered (router signal)
        self.arp_claims: dict[str, Counter[str]] = {}  # MAC -> IPs it claimed in ARP
        # services
        self.dns_servers: Counter[str] = Counter()
        self.dns_clients: Counter[str] = Counter()
        self.names: dict[str, str] = {}  # public IP -> a DNS name that resolved to it (for labels)
        self.dhcp_servers: dict[str, dict[str, Any]] = {}
        # capture quality
        self.flows: dict[tuple, dict[str, Any]] = {}
        self.flows_dropped = 0
        self.midstream = 0
        self.ack_gaps = 0
        # evidence rows: frame -> (ts, src, dst, proto, info)
        self.rows: dict[int, tuple[float, str, str, str, str]] = {}
        # inferred after the pass
        self.gateway_ip: str | None = None
        self.gateway_mac: str | None = None
        self.has_ethernet = False
        self.extra_notes: list[str] = []  # coverage notes added by detectors
        # traffic views
        self.activity: dict[int, Counter[str]] = {}  # whole second -> packets per transport
        self.conversations: dict[tuple[str, str, str], list] = {}  # (a, b, proto) -> [pkts, bytes, first frame, first, last]
        # per-MAC IP traffic: what each device received for / sent from which IPs (relay = man in the middle)
        self.mac_rx: dict[str, Counter[str]] = {}
        self.mac_tx: dict[str, Counter[str]] = {}

    # ---------------------------------------------------------------- feeding
    def feed(self, v: PacketView) -> None:
        self.packets += 1
        self.bytes += v.length
        self.start = v.ts if self.start is None else min(self.start, v.ts)
        self.end = v.ts if self.end is None else max(self.end, v.ts)
        self.protocols[v.proto] += 1
        self.links[v.link] += 1
        if v.eth_src:
            self.has_ethernet = True
            if is_unicast_mac(v.eth_src):
                self._bump(self.mac_pkts, v.eth_src)
        transport = "ARP" if v.arp else "TCP" if v.tcp else "UDP" if v.udp else "ICMP" if v.icmp else "Other"
        sec = int(v.ts)
        bucket = self.activity.get(sec)
        if bucket is None and len(self.activity) < 50_000:
            bucket = self.activity[sec] = Counter()
        if bucket is not None:
            bucket[transport] += 1
        if v.arp:
            self._feed_arp(v)
            self._conversation(v.arp[2], v.arp[4], "ARP", v)
            return
        if not v.ip_src:
            return
        self._conversation(v.ip_src, v.ip_dst, transport, v)
        if v.eth_src and is_unicast_mac(v.eth_src):
            self._add_ip_mac(self.mac_tx, v.eth_src, v.ip_src)
        if v.eth_dst and is_unicast_mac(v.eth_dst):
            self._add_ip_mac(self.mac_rx, v.eth_dst, v.ip_dst)
        self.talkers[v.ip_src] += v.length
        if len(self.talkers) > self.cfg["max_hosts"] * 2:
            self.talkers = Counter(dict(self.talkers.most_common(self.cfg["max_hosts"])))
        if v.eth_src and is_unicast_mac(v.eth_src):
            if ip_kind(v.ip_src) == "private":
                self._add_ip_mac(self.ip_traffic_macs, v.ip_src, v.eth_src)
                self._add_ip_mac(self.ip_macs, v.ip_src, v.eth_src)
            elif ip_kind(v.ip_src) == "public":
                seen = self.mac_public.setdefault(v.eth_src, set())
                if len(seen) < 200:
                    seen.add(v.ip_src)
        if v.dns:
            if v.dns["qr"]:
                self._bump(self.dns_servers, v.ip_src)
                for _rr, rtype, rdata, _ttl in v.dns["answers"]:
                    if rtype == 1 and len(self.names) < 20_000 and rdata not in self.names:
                        self.names[rdata] = v.dns["qname"]
            else:
                self._bump(self.dns_clients, v.ip_src)
        if v.dhcp and v.dhcp["type"] in (2, 5):  # OFFER / ACK
            self._feed_dhcp(v)
        if v.tcp:
            self._feed_tcp(v)

    def _conversation(self, a: str, b: str, proto: str, v: PacketView) -> None:
        key = (a, b, proto) if a <= b else (b, a, proto)
        c = self.conversations.get(key)
        if c is None:
            if len(self.conversations) >= 20_000:
                return
            c = self.conversations[key] = [0, 0, v.frame, v.ts, v.ts]
        c[0] += 1
        c[1] += v.length
        c[4] = v.ts

    def relayed(self, mac: str, own_ips: set[str]) -> tuple[int, int]:
        """Packets a device received for other addresses, and sent from other addresses (forwarding)."""
        rx = sum(n for ip, n in self.mac_rx.get(mac, {}).items() if ip not in own_ips)
        tx = sum(n for ip, n in self.mac_tx.get(mac, {}).items() if ip not in own_ips)
        return rx, tx

    def activity_series(self, bins: int = 120) -> list[dict[str, Any]]:
        """Packets per time bin per transport, relative to capture start."""
        if not self.activity or self.start is None:
            return []
        width = max(1, int(self.duration // bins) + 1)
        out: dict[int, Counter[str]] = {}
        for sec, counts in self.activity.items():
            b = int((sec - int(self.start)) // width) * width
            out.setdefault(b, Counter()).update(counts)
        return [{"t": t, "width": width, **dict(c)} for t, c in sorted(out.items())]

    def top_conversations(self, n: int = 50) -> list[dict[str, Any]]:
        rows = sorted(self.conversations.items(), key=lambda kv: -kv[1][1])[:n]
        return [{"a": a, "b": b, "proto": p, "packets": c[0], "bytes": c[1], "first_frame": c[2],
                 "first": round(c[3] - (self.start or c[3]), 3), "duration": round(c[4] - c[3], 3)}
                for (a, b, p), c in rows]

    def _bump(self, counter: Counter[str], key: str) -> None:
        if key in counter or len(counter) < self.cfg["max_hosts"]:
            counter[key] += 1

    def _add_ip_mac(self, table: dict[str, Counter[str]], ip: str, mac: str) -> None:
        if ip not in table:
            if len(table) >= self.cfg["max_hosts"]:
                return
            table[ip] = Counter()
        if mac in table[ip] or len(table[ip]) < 16:
            table[ip][mac] += 1

    def _feed_arp(self, v: PacketView) -> None:
        op, hwsrc, psrc, _hwdst, _pdst = v.arp
        if hwsrc and is_unicast_mac(hwsrc) and ip_kind(psrc) == "private":
            self._add_ip_mac(self.ip_macs, psrc, hwsrc)
            claims = self.arp_claims.setdefault(hwsrc, Counter()) if len(self.arp_claims) < self.cfg["max_hosts"] else None
            if claims is not None and (psrc in claims or len(claims) < 64):
                claims[psrc] += 1

    def _feed_dhcp(self, v: PacketView) -> None:
        d = v.dhcp
        sid = d["server_id"] or v.ip_src
        if sid not in self.dhcp_servers and len(self.dhcp_servers) >= 64:
            return
        entry = self.dhcp_servers.setdefault(sid, {
            "server_id": sid, "ip": v.ip_src, "mac": v.eth_src, "offers": 0, "acks": 0,
            "routers": Counter(), "dns": Counter(), "first_ts": v.ts, "last_ts": v.ts,
            "frames": [], "clients": set(),
        })
        entry["offers" if d["type"] == 2 else "acks"] += 1
        entry["last_ts"] = v.ts
        for r in d["router"]:
            entry["routers"][r] += 1
        for s in d["dns"]:
            entry["dns"][s] += 1
        if len(entry["frames"]) < 200:
            entry["frames"].append(v.frame)
        if d["chaddr"] and len(entry["clients"]) < 500:
            entry["clients"].add(d["chaddr"])
        self.remember(v)

    def _feed_tcp(self, v: PacketView) -> None:
        sport, dport, flags, seq, ack, _win, plen = v.tcp
        a, b = (v.ip_src, sport), (v.ip_dst, dport)
        key = (a, b) if a <= b else (b, a)
        direction = 0 if a <= b else 1
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= self.cfg["max_flows"]:
                self.flows_dropped += 1
                return
            flow = {"syn": bool(flags & SYN), "next": [None, None], "gaps": 0}
            self.flows[key] = flow
            if not flags & SYN and not flags & RST:
                self.midstream += 1
        end = seq + plen + (1 if flags & (SYN | FIN) else 0)
        nxt = flow["next"]
        if nxt[direction] is None or (end - nxt[direction]) % (1 << 32) < (1 << 31):
            nxt[direction] = end
        other = nxt[1 - direction]
        if flags & ACK and other is not None and plen == 0:
            ahead = (ack - other) % (1 << 32)
            if 0 < ahead < (1 << 31):
                # the receiver acknowledges bytes we never saw: capture dropped packets
                flow["gaps"] += 1
                self.ack_gaps += 1
                nxt[1 - direction] = ack

    # --------------------------------------------------------------- evidence
    def remember(self, v: PacketView, info: str | None = None) -> None:
        """Keep a one-line summary of a packet so it can be shown as evidence."""
        if v.frame in self.rows or len(self.rows) >= self.cfg["max_rows"]:
            return
        src = v.ip_src or (v.arp[2] if v.arp else v.eth_src) or "?"
        dst = v.ip_dst or (v.arp[4] if v.arp else v.eth_dst) or "?"
        self.rows[v.frame] = (v.ts, src, dst, v.proto, info or describe(v))

    def remember_row(self, frame: int, ts: float, src: str, dst: str, proto: str, info: str) -> None:
        if frame not in self.rows and len(self.rows) < self.cfg["max_rows"]:
            self.rows[frame] = (ts, src, dst, proto, info)

    # --------------------------------------------------------------- after pass
    def finalize(self) -> None:
        """Infer the gateway once all packets are seen."""
        best = max(self.mac_public.items(), key=lambda kv: len(kv[1]), default=(None, set()))
        if best[0] and len(best[1]) >= 2:
            self.gateway_mac = best[0]
            claims = self.arp_claims.get(best[0])
            if claims:
                self.gateway_ip = claims.most_common(1)[0][0]
            else:
                owned = [ip for ip, macs in self.ip_traffic_macs.items() if best[0] in macs]
                self.gateway_ip = owned[0] if owned else None
        if not self.gateway_ip and self.dhcp_servers:
            routers: Counter[str] = Counter()
            for entry in self.dhcp_servers.values():
                routers.update(entry["routers"])
            if routers:
                self.gateway_ip = routers.most_common(1)[0][0]

    def roles(self, ip: str) -> list[str]:
        out = []
        if ip == self.gateway_ip:
            out.append("gateway")
        if self.dns_servers.get(ip, 0) > 0:
            out.append("DNS server")
        if any(e["ip"] == ip or e["server_id"] == ip for e in self.dhcp_servers.values()):
            out.append("DHCP server")
        return out

    def devices(self) -> list[dict[str, Any]]:
        """Local devices: one row per (IP, MAC) pair, busiest first."""
        rows = []
        for ip, macs in self.ip_macs.items():
            for mac, count in macs.most_common(4):
                rows.append({
                    "ip": ip, "mac": mac, "vendor": vendor(mac), "role": ", ".join(self.roles(ip)),
                    "packets": self.mac_pkts.get(mac, count),
                })
        if not rows:  # no MAC information: list local IPs only
            for ip, _ in self.talkers.most_common(200):
                if ip_kind(ip) == "private":
                    rows.append({"ip": ip, "mac": "-", "vendor": "-", "role": ", ".join(self.roles(ip)),
                                 "packets": 0})
        rows.sort(key=lambda r: (-r["packets"], r["ip"]))
        return rows[:500]

    def device_label(self, ip: str | None = None, mac: str | None = None) -> str:
        """Human label like '192.168.1.30 (Raspberry Pi)'."""
        if ip and not mac and ip in self.ip_macs and self.ip_macs[ip]:
            mac = self.ip_macs[ip].most_common(1)[0][0]
        name = vendor(mac) if mac else ""
        role = self.roles(ip)[0] if ip and self.roles(ip) else ""
        bits = [b for b in (role, name if name not in ("Unknown", "") else "") if b]
        if ip and not bits and ip in self.names and ip_kind(ip) == "public":
            bits = [self.names[ip]]
        base = ip or mac or "?"
        return f"{base} ({', '.join(bits)})" if bits else base

    @property
    def duration(self) -> float:
        if self.start is None or self.end is None:
            return 0.0
        return max(0.0, self.end - self.start)


def describe(v: PacketView) -> str:
    """Short Wireshark-style info column for one packet."""
    if v.arp:
        op, hwsrc, psrc, _hwdst, pdst = v.arp
        if op == 1:
            if psrc == pdst:
                return f"Gratuitous ARP: {psrc} is at {hwsrc}"
            if psrc == "0.0.0.0":
                return f"ARP probe: who has {pdst}?"
            return f"Who has {pdst}? Tell {psrc}"
        return f"{psrc} is at {hwsrc}"
    if v.dns:
        d = v.dns
        if not d["qr"]:
            return f"DNS query 0x{d['id']:04x} {d['qname']}"
        rc = {0: "", 2: " SERVFAIL", 3: " NXDOMAIN", 5: " REFUSED"}.get(d["rcode"], f" rcode={d['rcode']}")
        ans = ", ".join(a[2] for a in d["answers"][:3])
        return f"DNS response 0x{d['id']:04x} {d['qname']}{rc}{' → ' + ans if ans else ''}"
    if v.dhcp:
        d = v.dhcp
        name = {1: "Discover", 2: "Offer", 3: "Request", 5: "ACK", 6: "NAK"}.get(d["type"], "BOOTP")
        extra = ""
        if d["type"] in (2, 5):
            extra = f" offering {d['yiaddr']}, router {'/'.join(d['router']) or '-'}, DNS {'/'.join(d['dns']) or '-'}"
        return f"DHCP {name}{extra}"
    if v.tcp:
        sport, dport, flags, seq, ack, win, plen = v.tcp
        return f"{sport} → {dport} [{flags_text(flags)}] Seq={seq} Ack={ack} Win={win} Len={plen}"
    if v.icmp:
        t, c, mtu, _inner = v.icmp
        if t == 3 and c == 4:
            return f"ICMP fragmentation needed (next-hop MTU {mtu})"
        return {0: "ICMP echo reply", 8: "ICMP echo request", 11: "ICMP time exceeded"}.get(
            t, f"ICMP type {t} code {c}")
    if v.udp:
        return f"{v.udp[0]} → {v.udp[1]} Len={v.udp[2]}"
    return v.proto
