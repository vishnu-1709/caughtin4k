"""Craft labelled sample captures with Scapy (deterministic). Run: python generate_samples.py

Every scenario sits on top of realistic background traffic (ARP, DNS, HTTPS sessions, NTP)
so detection is never trivially easy. Nothing here touches a real network: packets are only
written to files in samples/.
"""
from __future__ import annotations

import json
import os
import random
from typing import Callable

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, TCPerror
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
EPOCH = 1793520000.0  # 2026-11-01 (fixed so files are reproducible)
BCAST = "ff:ff:ff:ff:ff:ff"

GW = ("192.168.1.1", "50:c7:bf:3a:10:01")  # TP-Link router: gateway, DNS forwarder, DHCP server
LAPTOP = ("192.168.1.10", "18:66:da:4b:22:10")  # Dell
MACBOOK = ("192.168.1.20", "a4:83:e7:5c:33:20")  # Apple
PI = ("192.168.1.30", "b8:27:eb:6d:44:30")  # Raspberry Pi
PRINTER = ("192.168.1.40", "3c:d9:2b:7e:55:40")  # HP
ATTACKER = ("192.168.1.66", "dc:a6:32:9f:66:66")  # another Raspberry Pi, used as the attacker
NAS = ("192.168.1.5", "00:11:32:aa:bb:05")  # Synology NAS (internal file server)
HOSTS = [LAPTOP, MACBOOK, PI, PRINTER]

SITES = {
    "example.com": "93.184.215.14", "github.com": "140.82.121.4", "wikipedia.org": "185.15.59.224",
    "python.org": "151.101.0.223", "stackoverflow.com": "198.252.206.1", "iiitdm.ac.in": "14.139.160.66",
    "cloudflare.com": "104.16.132.229", "debian.org": "151.101.66.132", "mozilla.org": "34.149.97.1",
    "ubuntu.com": "185.125.190.20",
}


class Net:
    """Collects timed packets and writes them sorted by time."""

    def __init__(self, seed: int) -> None:
        self.rng = random.Random(seed)
        self.pkts: list = []
        self.dns_id = 0x1000

    def add(self, t: float, pkt) -> None:
        pkt.time = EPOCH + round(t, 6)
        self.pkts.append(pkt)

    def write(self, name: str) -> str:
        path = os.path.join(OUT, name)
        self.pkts.sort(key=lambda p: float(p.time))
        wrpcap(path, self.pkts)
        return path

    # ---------------------------------------------------------------- ARP
    def arp_request(self, t: float, src: tuple, target_ip: str) -> None:
        self.add(t, Ether(src=src[1], dst=BCAST) / ARP(op=1, hwsrc=src[1], psrc=src[0], pdst=target_ip))

    def arp_reply(self, t: float, claimed_ip: str, mac: str, to: tuple, eth_src: str | None = None) -> None:
        self.add(t, Ether(src=eth_src or mac, dst=to[1]) /
                 ARP(op=2, hwsrc=mac, psrc=claimed_ip, hwdst=to[1], pdst=to[0]))

    def arp_exchange(self, t: float, asker: tuple, owner: tuple) -> None:
        self.arp_request(t, asker, owner[0])
        self.arp_reply(t + self.rng.uniform(0.0005, 0.003), owner[0], owner[1], asker)

    def gratuitous(self, t: float, host: tuple) -> None:
        self.add(t, Ether(src=host[1], dst=BCAST) /
                 ARP(op=1, hwsrc=host[1], psrc=host[0], hwdst="00:00:00:00:00:00", pdst=host[0]))

    # ---------------------------------------------------------------- DNS
    def dns(self, t: float, client: tuple, qname: str, answer: str | None = None, server: tuple = GW,
            rcode: int = 0, delay: float | None = None, reply: bool = True, answer_ttl: int = 300,
            server_mac: str | None = None) -> int:
        """Query + optional response. Returns the transaction id."""
        self.dns_id = (self.dns_id + self.rng.randint(1, 97)) & 0xFFFF
        qid, sport = self.dns_id, self.rng.randint(32768, 60999)
        l2_dst = server_mac or (server[1] if server[0].startswith("192.168.") else GW[1])
        self.add(t, Ether(src=client[1], dst=l2_dst) / IP(src=client[0], dst=server[0], ttl=64) /
                 UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=qname)))
        if reply:
            delay = self.rng.uniform(0.008, 0.035) if delay is None else delay
            an = DNSRR(rrname=qname, type="A", ttl=answer_ttl, rdata=answer) if (answer and rcode == 0) else None
            self.add(t + delay, Ether(src=l2_dst, dst=client[1]) / IP(src=server[0], dst=client[0], ttl=64) /
                     UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, rd=1, ra=1, rcode=rcode,
                                                      qd=DNSQR(qname=qname), an=an))
        return qid

    # ---------------------------------------------------------------- TCP
    def tcp_session(self, t: float, client: tuple, server_ip: str, dport: int = 443, rtt: float = 0.03,
                    segments: int = 4, handshake_delay: float | None = None, retrans: set[int] | None = None,
                    retrans_wait: float = 0.3, server_mac: str | None = None, client_l2_dst: str | None = None,
                    seg_size: int = 1400, sport: int | None = None, close: bool = True,
                    relay: str | None = None) -> float:
        """Full HTTPS-like conversation. Returns the end time.

        retrans: indices of server data segments that are lost once and re-sent.
        relay: MAC of a man-in-the-middle; every packet goes to it first and it forwards a copy on.
        """
        rng = self.rng
        sport = sport or rng.randint(49152, 65000)
        local = server_ip.startswith("192.168.")
        srv_mac = server_mac or (GW[1] if not local else server_mac)
        c_dst = relay or client_l2_dst or srv_mac
        ttl_s = 64 if local else rng.choice([52, 54, 57, 116])
        cseq, sseq = rng.randint(1, 2**31), rng.randint(1, 2**31)

        def c2s(tt: float, flags: str, payload: bytes = b"") -> None:
            nonlocal cseq
            p = Ether(src=client[1], dst=c_dst) / IP(src=client[0], dst=server_ip, ttl=64, flags="DF") / \
                TCP(sport=sport, dport=dport, flags=flags, seq=cseq, ack=sseq, window=64240)
            p = p / Raw(payload) if payload else p
            self.add(tt, p)
            if relay:  # the man in the middle forwards it to the real router
                fwd = p.copy()
                fwd[Ether].src, fwd[Ether].dst = relay, srv_mac
                self.add(tt + 0.0004, fwd)
            cseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

        def s2c(tt: float, flags: str, payload: bytes = b"", seq: int | None = None) -> None:
            nonlocal sseq
            use = sseq if seq is None else seq
            p = Ether(src=srv_mac, dst=relay or client[1]) / IP(src=server_ip, dst=client[0], ttl=ttl_s, flags="DF") / \
                TCP(sport=dport, dport=sport, flags=flags, seq=use, ack=cseq, window=65535)
            p = p / Raw(payload) if payload else p
            self.add(tt, p)
            if relay:
                fwd = p.copy()
                fwd[Ether].src, fwd[Ether].dst = relay, client[1]
                self.add(tt + 0.0004, fwd)
            if seq is None:
                sseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

        hs = rtt if handshake_delay is None else handshake_delay
        c2s(t, "S")
        s2c(t + hs, "SA")
        t += hs + 0.0005
        c2s(t, "A")
        c2s(t + 0.001, "PA", b"\x16\x03\x01" + bytes(rng.getrandbits(8) for _ in range(280)))
        t += rtt
        for i in range(segments):
            data = bytes(rng.getrandbits(8) for _ in range(seg_size))
            if retrans and i in retrans:
                lost_seq = sseq
                s2c(t, "A", data)  # original: lost further along the path
                c2s(t + 0.001, "A")  # client still acknowledges only the old data
                t += retrans_wait
                s2c(t, "A", data, seq=lost_seq)  # same seq, same payload: retransmission
            else:
                s2c(t, "A", data)
            t += 0.002
            if i % 2 == 1:
                c2s(t, "A")
        c2s(t + 0.01, "A")
        t += 0.05
        if close:
            c2s(t, "FA")
            s2c(t + rtt, "FA")
            c2s(t + rtt + 0.0005, "A")
            t += rtt
        return t

    # ---------------------------------------------------------------- DHCP
    def dhcp_dora(self, t: float, client_mac: str, offered: str, server: tuple, router: str, dns: str,
                  xid: int | None = None, respond: bool = True) -> None:
        xid = xid or self.rng.randint(1, 2**31)
        chaddr = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10
        base = Ether(src=client_mac, dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67)
        self.add(t, base / BOOTP(op=1, xid=xid, chaddr=chaddr) /
                 DHCP(options=[("message-type", "discover"), "end"]))
        if respond:
            self.dhcp_reply(t + 0.004, "offer", client_mac, offered, server, router, dns, xid)
        self.add(t + 0.02, base / BOOTP(op=1, xid=xid, chaddr=chaddr) /
                 DHCP(options=[("message-type", "request"), ("requested_addr", offered),
                               ("server_id", server[0]), "end"]))
        if respond:
            self.dhcp_reply(t + 0.024, "ack", client_mac, offered, server, router, dns, xid)

    def dhcp_reply(self, t: float, kind: str, client_mac: str, offered: str, server: tuple, router: str,
                   dns: str, xid: int) -> None:
        chaddr = bytes.fromhex(client_mac.replace(":", "")) + b"\x00" * 10
        self.add(t, Ether(src=server[1], dst=BCAST) / IP(src=server[0], dst="255.255.255.255") /
                 UDP(sport=67, dport=68) / BOOTP(op=2, xid=xid, yiaddr=offered, siaddr=server[0], chaddr=chaddr) /
                 DHCP(options=[("message-type", kind), ("server_id", server[0]), ("lease_time", 86400),
                               ("subnet_mask", "255.255.255.0"), ("router", router), ("name_server", dns),
                               "end"]))

    # ---------------------------------------------------------------- background
    def background(self, duration: float = 120.0, hosts: list | None = None, sessions: int = 26,
                   dns_queries: int = 30, skip: Callable[[float, tuple], bool] | None = None) -> None:
        """Ordinary office traffic: ARP, DNS lookups, HTTPS sessions, NTP."""
        hosts = hosts or HOSTS
        rng = self.rng
        for i, h in enumerate(hosts):
            self.arp_exchange(0.2 + i * 0.3, h, GW)
        for k in range(int(duration // 45)):
            for i, h in enumerate(hosts):
                self.arp_exchange(30 + k * 45 + i * 0.7, GW, h)
        names = list(SITES)
        for _ in range(dns_queries):
            t, h, name = rng.uniform(1, duration - 2), rng.choice(hosts), rng.choice(names)
            if skip and skip(t, h):
                continue
            self.dns(t, h, name, SITES[name])
        for _ in range(sessions):
            t, h, name = rng.uniform(1, duration - 8), rng.choice(hosts), rng.choice(names)
            if skip and skip(t, h):
                continue
            self.tcp_session(t, h, SITES[name], rtt=rng.uniform(0.02, 0.06), segments=rng.randint(2, 8))
        for i in range(int(duration // 40)):
            h = hosts[i % len(hosts)]
            self.add(5 + i * 40, Ether(src=h[1], dst=GW[1]) / IP(src=h[0], dst="162.159.200.1") /
                     UDP(sport=123, dport=123) / Raw(b"\x23" + b"\x00" * 47))
            self.add(5.03 + i * 40, Ether(src=GW[1], dst=h[1]) / IP(src="162.159.200.1", dst=h[0], ttl=57) /
                     UDP(sport=123, dport=123) / Raw(b"\x24" + b"\x00" * 47))


# ===================================================================== scenarios
def clean() -> Net:
    net = Net(1)
    net.background(120, sessions=30, dns_queries=40)
    return net


def arp_spoof() -> Net:
    """An attacker poisons the laptop and the router so traffic flows through it (MITM)."""
    net = Net(2)
    hosts = HOSTS + [ATTACKER]
    net.background(120, hosts=hosts)
    victim = LAPTOP
    for k in range(40):
        t = 30 + k * 2.0
        net.arp_reply(t, GW[0], ATTACKER[1], victim)  # "the router is at my MAC"
        net.arp_reply(t + 0.01, victim[0], ATTACKER[1], GW)  # "the laptop is at my MAC"
    # victim's traffic now goes via the attacker, which forwards it on
    for k in range(6):
        t = 40 + k * 10
        name = list(SITES)[k]
        net.tcp_session(t, victim, SITES[name], relay=ATTACKER[1], rtt=0.09, segments=3)
    return net


def duplicate_ip() -> Net:
    """Two devices are configured with the same static IP: an honest misconfiguration."""
    net = Net(3)
    net.background(120)
    a = ("192.168.1.50", "18:66:da:4b:22:50")  # Dell desktop, has .50 from the start
    b = ("192.168.1.50", "a4:83:e7:5c:33:51")  # Apple laptop, manually set to .50 later
    net.gratuitous(1.0, a)
    for t in (3, 20, 70):
        net.dns(t, a, "python.org", SITES["python.org"])
        net.tcp_session(t + 0.2, a, SITES["python.org"], segments=3)
    # b joins: ARP probe for .50 -> a defends it (conflict), b uses it anyway (static config)
    net.add(39.5, Ether(src=b[1], dst=BCAST) / ARP(op=1, hwsrc=b[1], psrc="0.0.0.0", pdst=a[0]))
    net.arp_reply(39.502, a[0], a[1], ("0.0.0.0", b[1]))
    net.gratuitous(41.0, b)
    for t in (45, 80, 100):
        net.dns(t, b, "github.com", SITES["github.com"])
        net.tcp_session(t + 0.2, b, SITES["github.com"], segments=3)
    # the router asks who has .50: both devices answer
    net.arp_request(60, GW, a[0])
    net.arp_reply(60.001, a[0], a[1], GW)
    net.arp_reply(60.002, b[0], b[1], GW)
    net.arp_request(105, GW, a[0])
    net.arp_reply(105.002, b[0], b[1], GW)
    net.arp_reply(105.003, a[0], a[1], GW)
    return net


def _syn(net: Net, t: float, src: tuple, dst: tuple, sport: int, dport: int) -> None:
    net.add(t, Ether(src=src[1], dst=dst[1]) / IP(src=src[0], dst=dst[0], ttl=64) /
            TCP(sport=sport, dport=dport, flags="S", seq=net.rng.randint(1, 2**31), window=1024))


def port_scan() -> Net:
    """The attacker SYN-scans the Raspberry Pi (Nmap style): 220 ports in ~6 seconds."""
    net = Net(4)
    net.background(120, hosts=HOSTS + [ATTACKER])
    target, open_ports = PI, {22, 80}
    ports = list(range(1, 201)) + [443, 445, 3306, 3389, 5900, 8080, 8443, 9100, 139, 631, 993, 995, 21, 23,
                                   25, 110, 143, 161, 389, 5432]
    sport = 61234
    for i, port in enumerate(sorted(set(ports))):
        t = 50 + i * 0.027
        _syn(net, t, ATTACKER, target, sport, port)
        if port in open_ports:
            net.add(t + 0.0004, Ether(src=target[1], dst=ATTACKER[1]) / IP(src=target[0], dst=ATTACKER[0], ttl=64) /
                    TCP(sport=port, dport=sport, flags="SA", seq=net.rng.randint(1, 2**31), ack=1))
            net.add(t + 0.0008, Ether(src=ATTACKER[1], dst=target[1]) / IP(src=ATTACKER[0], dst=target[0], ttl=64) /
                    TCP(sport=sport, dport=port, flags="R", seq=1))
        elif port % 7:  # most closed ports answer with RST; some are filtered (no reply)
            net.add(t + 0.0004, Ether(src=target[1], dst=ATTACKER[1]) / IP(src=target[0], dst=ATTACKER[0], ttl=64) /
                    TCP(sport=port, dport=sport, flags="RA", seq=0, ack=1))
    return net


def tcp_resets_service_down() -> Net:
    """The office NAS's file-sharing service (SMB, 445) has stopped: every client is refused."""
    net = Net(5)
    net.background(120)
    for i, h in enumerate([LAPTOP, MACBOOK, PI, LAPTOP, MACBOOK, LAPTOP, PI, MACBOOK]):
        for retry in range(2):
            t = 20 + i * 11 + retry * 0.6
            sport = 50000 + i * 10 + retry
            _syn(net, t, h, NAS, sport, 445)
            net.add(t + 0.0006, Ether(src=NAS[1], dst=h[1]) / IP(src=NAS[0], dst=h[0], ttl=64) /
                    TCP(sport=445, dport=sport, flags="RA", seq=0, ack=1))
    net.arp_exchange(19.5, LAPTOP, NAS)
    return net


def tcp_retransmissions() -> Net:
    """The MacBook on weak Wi-Fi: its downloads keep losing packets."""
    net = Net(6)
    net.background(120)
    for k in range(5):
        t = 20 + k * 18
        lost = set(net.rng.sample(range(24), 6))
        net.tcp_session(t, MACBOOK, SITES["debian.org"], segments=24, retrans=lost, retrans_wait=0.25, rtt=0.05)
    return net


def dns_failures() -> Net:
    """The router's DNS forwarder loses its upstream: queries time out, then return SERVFAIL."""
    net = Net(7)
    outage = (40.0, 85.0)
    net.background(120, skip=lambda t, h: outage[0] <= t <= outage[1])
    names = list(SITES)
    for k in range(18):
        t = outage[0] + k * 1.4
        h = HOSTS[k % 4]
        net.dns(t, h, names[k % len(names)], reply=False)
        net.dns(t + 1.0, h, names[k % len(names)], reply=False)  # retry, also unanswered
    for k in range(8):
        t = 66 + k * 2.2
        net.dns(t, HOSTS[k % 4], names[(k + 3) % len(names)], rcode=2, delay=0.9)
    return net


def rogue_dhcp_dns_hijack() -> Net:
    """A rogue DHCP server makes itself DNS; it then answers 'github.com' with its own address."""
    net = Net(8)
    hosts = HOSTS + [ATTACKER]
    net.background(120, hosts=hosts)
    phone = ("192.168.1.77", "8c:85:90:12:34:77")  # an Apple phone joining the Wi-Fi
    tablet = ("192.168.1.78", "f4:f5:d8:ab:cd:78")  # a Google tablet joining later
    # legit DHCP for the tablet, rogue wins the race for the phone
    xid = 0x5A5A1001
    net.add(30.0, Ether(src=phone[1], dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=bytes.fromhex(phone[1].replace(":", "")) + b"\0" * 10) /
            DHCP(options=[("message-type", "discover"), "end"]))
    net.dhcp_reply(30.002, "offer", phone[1], phone[0], ATTACKER, ATTACKER[0], ATTACKER[0], xid)  # rogue: fast
    net.dhcp_reply(30.009, "offer", phone[1], "192.168.1.120", GW, GW[0], GW[0], xid)  # real: slower
    net.add(30.02, Ether(src=phone[1], dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) / BOOTP(op=1, xid=xid, chaddr=bytes.fromhex(phone[1].replace(":", "")) + b"\0" * 10) /
            DHCP(options=[("message-type", "request"), ("requested_addr", phone[0]), ("server_id", ATTACKER[0]), "end"]))
    net.dhcp_reply(30.023, "ack", phone[1], phone[0], ATTACKER, ATTACKER[0], ATTACKER[0], xid)
    net.dhcp_dora(70.0, tablet[1], tablet[0], GW, GW[0], GW[0])
    # the phone now uses the attacker as DNS: real-looking answers, except github.com -> attacker
    for k, name in enumerate(["example.com", "github.com", "wikipedia.org", "github.com", "python.org", "github.com"]):
        t = 32 + k * 9
        answer = ATTACKER[0] if name == "github.com" else SITES[name]
        net.dns(t, phone, name, answer, server=ATTACKER, answer_ttl=60)
        if name != "github.com":
            net.tcp_session(t + 0.1, phone, SITES[name], client_l2_dst=ATTACKER[1], segments=2)
    # the tablet uses the real DNS and gets the real github address
    net.dns(75, tablet, "github.com", SITES["github.com"])
    return net


def mixed_attack_and_fault() -> Net:
    """ARP spoofing slows the laptop down (it now loses packets), while the NAS service is down."""
    net = Net(9)
    net.background(150, hosts=HOSTS + [ATTACKER], sessions=34)
    victim = LAPTOP
    for k in range(45):
        t = 40 + k * 2.0
        net.arp_reply(t, GW[0], ATTACKER[1], victim)
        net.arp_reply(t + 0.01, victim[0], ATTACKER[1], GW)
    for k in range(5):  # traffic via the attacker: slower and lossy
        t = 48 + k * 15
        lost = set(net.rng.sample(range(16), 4))
        net.tcp_session(t, victim, SITES["github.com"], relay=ATTACKER[1], segments=16, retrans=lost,
                        retrans_wait=0.4, rtt=0.12)
    for i, h in enumerate([MACBOOK, PI, MACBOOK, PI, MACBOOK]):  # unrelated fault: NAS file sharing down
        t = 25 + i * 20
        _syn(net, t, h, NAS, 51000 + i, 445)
        net.add(t + 0.0006, Ether(src=NAS[1], dst=h[1]) / IP(src=NAS[0], dst=h[0], ttl=64) /
                TCP(sport=445, dport=51000 + i, flags="RA", seq=0, ack=1))
    return net


def slow_handshakes() -> Net:
    """The college web server is overloaded: it takes 1-2.5 s to accept each connection."""
    net = Net(10)
    net.background(120)
    slow_ip = SITES["iiitdm.ac.in"]
    for k in range(7):
        t = 15 + k * 13
        h = HOSTS[k % 3]
        net.dns(t, h, "iiitdm.ac.in", slow_ip)
        net.tcp_session(t + 0.05, h, slow_ip, handshake_delay=net.rng.uniform(1.1, 2.5), rtt=0.04, segments=3)
    return net


def malicious_xss_dnsname() -> Net:
    """A device keeps looking up a name that contains HTML/JavaScript. The tool must show it as plain text."""
    net = Net(11)
    net.background(90)
    evil = "<script>alert(document.cookie)</script>.example.com"
    evil2 = '<img src=x onerror="alert(1)">.example.com'
    for k in range(12):
        net.dns(10 + k * 6, PI, evil if k % 2 else evil2, rcode=3)
    return net


def _upload(net: Net, t: float, client: tuple, server_ip: str, sizes: list[int], lost: set[int],
            icmp_mtu: int | None = None) -> None:
    """Client sends a small request then big DF segments. Segments in `lost` are dropped on the path:
    the router either reports it (ICMP frag-needed) or stays silent (black hole)."""
    rng = net.rng
    sport, cseq, sseq = rng.randint(49152, 65000), rng.randint(1, 2**31), rng.randint(1, 2**31)

    def c2s(tt, flags, payload=b""):
        net.add(tt, Ether(src=client[1], dst=GW[1]) / IP(src=client[0], dst=server_ip, flags="DF", ttl=64) /
                TCP(sport=sport, dport=443, flags=flags, seq=cseq, ack=sseq, window=64240) / Raw(payload)
                if payload else Ether(src=client[1], dst=GW[1]) / IP(src=client[0], dst=server_ip, flags="DF") /
                TCP(sport=sport, dport=443, flags=flags, seq=cseq, ack=sseq, window=64240))

    def s2c(tt, flags, ack):
        net.add(tt, Ether(src=GW[1], dst=client[1]) / IP(src=server_ip, dst=client[0], ttl=54, flags="DF") /
                TCP(sport=443, dport=sport, flags=flags, seq=sseq, ack=ack, window=65535))

    c2s(t, "S"); cseq += 1
    s2c(t + 0.03, "SA", cseq); sseq += 1
    c2s(t + 0.031, "A")
    req = b"\x17\x03\x03" + bytes(rng.getrandbits(8) for _ in range(200))
    c2s(t + 0.032, "PA", req); cseq += len(req)
    s2c(t + 0.062, "A", cseq)
    t += 0.07
    for i, size in enumerate(sizes):
        data = bytes(rng.getrandbits(8) for _ in range(size))
        if i in lost:
            for attempt in range(4 if icmp_mtu is None else 1):
                c2s(t + attempt * 0.4 * (2 ** attempt), "PA", data)  # same seq: retransmissions
                if icmp_mtu:
                    inner = IPerror(src=client[0], dst=server_ip, flags="DF", len=size + 40, proto=6) / \
                        TCPerror(sport=sport, dport=443, seq=cseq)
                    net.add(t + 0.002, Ether(src=GW[1], dst=client[1]) / IP(src=GW[0], dst=client[0]) /
                            ICMP(type=3, code=4, nexthopmtu=icmp_mtu) / inner)
            if icmp_mtu:  # sender obeys: re-sends the data in two smaller pieces
                half = len(data) // 2
                c2s(t + 0.01, "PA", data[:half]); cseq += half
                c2s(t + 0.011, "PA", data[half:]); cseq += len(data) - half
                s2c(t + 0.05, "A", cseq)
            t += 4.0
        else:
            c2s(t, "PA", data); cseq += size
            s2c(t + 0.03, "A", cseq)
            t += 0.05


def mtu() -> Net:
    """A VPN link with MTU 1400: the router reports it for one laptop; another path silently drops big packets."""
    net = Net(12)
    net.background(120)
    for k in range(3):
        _upload(net, 20 + k * 15, LAPTOP, "185.125.190.20", [1460, 1460, 600, 1460], lost={0, 1, 3}, icmp_mtu=1400)
    _upload(net, 70, MACBOOK, "104.16.132.229", [400, 1460], lost={1})
    return net


def router_replacement() -> Net:
    """Harmless look-alike of ARP spoofing: the router is swapped for a new one (new MAC) at t=55 s."""
    net = Net(13)
    net.background(120)
    new_mac = "a0:40:a0:77:88:01"  # Netgear
    swap = EPOCH + 55.0
    for p in net.pkts:
        if float(p.time) < swap:
            continue
        eth = p.getlayer(Ether)
        if eth.src == GW[1]:
            eth.src = new_mac
        if eth.dst == GW[1]:
            eth.dst = new_mac
        arp = p.getlayer(ARP)
        if arp is not None:
            if arp.hwsrc == GW[1]:
                arp.hwsrc = new_mac
            if arp.hwdst == GW[1]:
                arp.hwdst = new_mac
    new_gw = (GW[0], new_mac)
    net.gratuitous(55.2, new_gw)
    for i, h in enumerate(HOSTS):  # devices notice the change and ask again; the new router answers
        net.arp_exchange(58 + i * 0.5, h, new_gw)
    return net


def busy_browsing() -> Net:
    """Harmless look-alike of a sweep: a laptop opens a news site that loads from 22 different servers."""
    net = Net(14)
    net.background(120)
    for k in range(22):
        ip = f"151.101.{(k * 37) % 250 + 1}.{(k * 11) % 250 + 2}"
        net.tcp_session(30 + k * 0.4, LAPTOP, ip, rtt=0.03, segments=3)
    return net


def backup_dhcp() -> Net:
    """Harmless look-alike of rogue DHCP: a second, correctly configured DHCP server (a Windows server)."""
    net = Net(15)
    net.background(120)
    server2 = ("192.168.1.2", "00:15:5d:01:02:02")  # Microsoft Hyper-V
    phone = ("192.168.1.77", "8c:85:90:12:34:77")
    xid = 0x5A5A2002
    chaddr = bytes.fromhex(phone[1].replace(":", "")) + b"\0" * 10
    net.add(30.0, Ether(src=phone[1], dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
            BOOTP(op=1, xid=xid, chaddr=chaddr) / DHCP(options=[("message-type", "discover"), "end"]))
    net.dhcp_reply(30.003, "offer", phone[1], phone[0], GW, GW[0], GW[0], xid)
    net.dhcp_reply(30.006, "offer", phone[1], "192.168.1.150", server2, GW[0], GW[0], xid)
    net.add(30.02, Ether(src=phone[1], dst=BCAST) / IP(src="0.0.0.0", dst="255.255.255.255") / UDP(sport=68, dport=67) /
            BOOTP(op=1, xid=xid, chaddr=chaddr) / DHCP(options=[("message-type", "request"),
                                                                 ("requested_addr", phone[0]), ("server_id", GW[0]), "end"]))
    net.dhcp_reply(30.023, "ack", phone[1], phone[0], GW, GW[0], GW[0], xid)
    net.dhcp_dora(80.0, "f4:f5:d8:ab:cd:78", "192.168.1.151", server2, GW[0], GW[0])
    return net


def attack_chain() -> Net:
    """Multi-step attack: scan the router, poison ARP (MITM), then forge DNS for a bank site."""
    net = Net(16)
    net.background(150, hosts=HOSTS + [ATTACKER])
    victim = LAPTOP
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    for i, port in enumerate(ports):  # step 1: what is the router running?
        t = 10 + i * 0.05
        _syn(net, t, ATTACKER, GW, 40000 + i, port)
        net.add(t + 0.0005, Ether(src=GW[1], dst=ATTACKER[1]) / IP(src=GW[0], dst=ATTACKER[0], ttl=64) /
                TCP(sport=port, dport=40000 + i, flags="SA" if port in (53, 80, 443) else "RA", seq=7, ack=1))
    for k in range(50):  # step 2: become the man in the middle
        t = 25 + k * 2.0
        net.arp_reply(t, GW[0], ATTACKER[1], victim)
        net.arp_reply(t + 0.01, victim[0], ATTACKER[1], GW)
    for k in range(4):
        net.tcp_session(32 + k * 20, victim, SITES["wikipedia.org"], relay=ATTACKER[1], segments=3)
    for k in range(4):  # step 3: forge DNS answers for the bank, racing the real resolver
        t = 45 + k * 22
        net.dns_id = (net.dns_id + 7) & 0xFFFF
        qid, sport = net.dns_id, 53000 + k
        q = Ether(src=victim[1], dst=ATTACKER[1]) / IP(src=victim[0], dst=GW[0]) / UDP(sport=sport, dport=53) / \
            DNS(id=qid, rd=1, qd=DNSQR(qname="bank.example.com"))
        net.add(t, q)
        forged = Ether(src=ATTACKER[1], dst=victim[1]) / IP(src=GW[0], dst=victim[0], ttl=64) / \
            UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname="bank.example.com"),
                                             an=DNSRR(rrname="bank.example.com", ttl=30, rdata=ATTACKER[0]))
        net.add(t + 0.002, forged)
        real = Ether(src=GW[1], dst=ATTACKER[1]) / IP(src=GW[0], dst=victim[0], ttl=64) / \
            UDP(sport=53, dport=sport) / DNS(id=qid, qr=1, rd=1, ra=1, qd=DNSQR(qname="bank.example.com"),
                                             an=DNSRR(rrname="bank.example.com", ttl=300, rdata="203.0.113.50"))
        net.add(t + 0.03, real)
    return net


def cleartext_logins() -> Net:
    """Passwords sent unencrypted: FTP to the NAS and a plain-HTTP router admin login."""
    net = Net(17)
    net.background(120)

    def plain(t, client, server, dport, lines):
        sport = net.rng.randint(49152, 65000)
        cseq, sseq = net.rng.randint(1, 2**31), net.rng.randint(1, 2**31)
        net.add(t, Ether(src=client[1], dst=server[1]) / IP(src=client[0], dst=server[0]) /
                TCP(sport=sport, dport=dport, flags="S", seq=cseq))
        net.add(t + 0.001, Ether(src=server[1], dst=client[1]) / IP(src=server[0], dst=client[0]) /
                TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        cseq += 1
        sseq += 1
        net.add(t + 0.002, Ether(src=client[1], dst=server[1]) / IP(src=client[0], dst=server[0]) /
                TCP(sport=sport, dport=dport, flags="A", seq=cseq, ack=sseq))
        tt = t + 0.01
        for who, text in lines:
            data = text.encode()
            if who == "c":
                net.add(tt, Ether(src=client[1], dst=server[1]) / IP(src=client[0], dst=server[0]) /
                        TCP(sport=sport, dport=dport, flags="PA", seq=cseq, ack=sseq) / Raw(data))
                cseq += len(data)
            else:
                net.add(tt, Ether(src=server[1], dst=client[1]) / IP(src=server[0], dst=client[0]) /
                        TCP(sport=dport, dport=sport, flags="PA", seq=sseq, ack=cseq) / Raw(data))
                sseq += len(data)
            tt += 0.05

    plain(30, PRINTER, NAS, 21, [("s", "220 NAS FTP ready\r\n"), ("c", "USER scanner\r\n"),
                                 ("s", "331 Password required\r\n"), ("c", "PASS Winter2026!\r\n"),
                                 ("s", "230 Logged in\r\n")])
    plain(70, LAPTOP, GW, 80, [("c", "POST /login.cgi HTTP/1.1\r\nHost: 192.168.1.1\r\nContent-Type: "
                                     "application/x-www-form-urlencoded\r\n\r\nusername=admin&password=admin123"),
                               ("s", "HTTP/1.1 302 Found\r\nLocation: /status.html\r\n\r\n")])
    return net


SCENARIOS: dict[str, tuple[Callable[[], Net], str, list[dict]]] = {
    "attack_chain.pcap": (attack_chain, "Multi-step attack: scan the router, intercept a laptop, fake a bank's address.",
                          [{"kind": "port_scan", "verdict": "attack"}, {"kind": "arp_spoofing", "verdict": "attack"},
                           {"kind": "dns_hijack", "verdict": "attack"}]),
    "cleartext_logins.pcap": (cleartext_logins, "Passwords sent unencrypted (FTP and a plain-HTTP admin page).",
                              [{"kind": "cleartext_credentials", "verdict": "fault"},
                               {"kind": "cleartext_credentials", "verdict": "fault"}]),
    "mixed_attack_and_fault.pcap": (mixed_attack_and_fault,
                                    "An attacker intercepts a laptop (and slows it down) while the NAS is down.",
                                    [{"kind": "arp_spoofing", "verdict": "attack"},
                                     {"kind": "tcp_retransmissions", "verdict": "fault"},
                                     {"kind": "service_refused", "verdict": "fault"}]),
    "clean.pcap": (clean, "A normal two-minute office capture with no problems.", []),
    "arp_spoof.pcap": (arp_spoof, "A device pretends to be the router to intercept a laptop's traffic.",
                       [{"kind": "arp_spoofing", "verdict": "attack"}]),
    "duplicate_ip.pcap": (duplicate_ip, "Two devices were given the same IP address by mistake.",
                          [{"kind": "duplicate_ip", "verdict": "fault"}]),
    "port_scan.pcap": (port_scan, "A device scans another for open ports (Nmap-style SYN scan).",
                       [{"kind": "port_scan", "verdict": "attack"}]),
    "rogue_dhcp_dns_hijack.pcap": (rogue_dhcp_dns_hijack,
                                   "A fake DHCP server makes itself the DNS server and redirects github.com.",
                                   [{"kind": "rogue_dhcp", "verdict": "attack"},
                                    {"kind": "dns_hijack", "verdict": "attack"}]),
    "dns_failures.pcap": (dns_failures, "The router's DNS stops answering for a while, then returns errors.",
                          [{"kind": "dns_timeout", "verdict": "fault"},
                           {"kind": "dns_servfail", "verdict": "fault"},
                           {"kind": "slow_dns", "verdict": "fault"}]),
    "tcp_retransmissions.pcap": (tcp_retransmissions, "A laptop on weak Wi-Fi keeps losing packets.",
                                 [{"kind": "tcp_retransmissions", "verdict": "fault"}]),
    "mtu.pcap": (mtu, "A link with a smaller MTU: big packets are rejected or silently dropped.",
                 [{"kind": "mtu_mismatch", "verdict": "fault"}, {"kind": "mtu_mismatch", "verdict": "fault"}]),
    "router_replacement.pcap": (router_replacement,
                                "Tricky but harmless: the router was replaced, so its MAC address changed.",
                                [{"kind": "ip_conflict", "verdict": "uncertain"}]),
    "busy_browsing.pcap": (busy_browsing, "Tricky but harmless: a laptop loads a page from 22 servers at once.", []),
    "backup_dhcp.pcap": (backup_dhcp, "Tricky but harmless: a second DHCP server with identical settings.",
                         [{"kind": "rogue_dhcp", "verdict": "fault"}]),
    "malicious_xss_dnsname.pcap": (malicious_xss_dnsname,
                                   "Malicious input: DNS names containing <script> code (must display as text).",
                                   [{"kind": "dns_nxdomain", "verdict": "fault"}]),
    "slow_handshakes.pcap": (slow_handshakes, "A busy web server takes seconds to accept connections.",
                             [{"kind": "slow_responses", "verdict": "fault"}]),
    "tcp_resets_service_down.pcap": (tcp_resets_service_down,
                                     "The file-sharing service on the office NAS has stopped.",
                                     [{"kind": "service_refused", "verdict": "fault"}]),
}


GROUPS = {
    "attack_chain.pcap": "Multi-step attack", "mixed_attack_and_fault.pcap": "Multi-step attack",
    "rogue_dhcp_dns_hijack.pcap": "Multi-step attack",
    "arp_spoof.pcap": "Attack", "port_scan.pcap": "Attack",
    "clean.pcap": "Healthy or harmless", "router_replacement.pcap": "Healthy or harmless",
    "busy_browsing.pcap": "Healthy or harmless", "backup_dhcp.pcap": "Healthy or harmless",
    "malicious_xss_dnsname.pcap": "Broken or hostile file", "broken_truncated.pcap": "Broken or hostile file",
    "not_a_pcap.pcap": "Broken or hostile file", "malformed_huge_record.pcap": "Broken or hostile file",
}


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    labels = {}
    for name, (build, description, expected) in SCENARIOS.items():
        net = build()
        net.write(name)
        labels[name] = {"description": description, "expected": expected}
        print(f"{name:32} {len(net.pkts):5} packets  {description}")
    # damaged inputs: a capture cut off mid-packet, and a file that is not a capture at all
    with open(os.path.join(OUT, "clean.pcap"), "rb") as fh:
        clean_bytes = fh.read()
    with open(os.path.join(OUT, "broken_truncated.pcap"), "wb") as fh:
        fh.write(clean_bytes[: len(clean_bytes) * 2 // 3 + 11])
    labels["broken_truncated.pcap"] = {"description": "Damaged input: a capture cut off in the middle of a packet.",
                                       "expected": [], "expect_partial": True}
    with open(os.path.join(OUT, "not_a_pcap.pcap"), "wb") as fh:
        fh.write(b"<html><body><script>alert('not a capture')</script></body></html>\n" * 20)
    labels["not_a_pcap.pcap"] = {"description": "Wrong input: a web page renamed to .pcap (must be rejected).",
                                 "expected": [], "expect_error": "not_pcap"}
    # a corrupt record that claims to hold 4 GB: the reader must stop cleanly, not allocate it
    import struct
    huge = clean_bytes[:24] + clean_bytes[24:24 + 16 + struct.unpack("<I", clean_bytes[32:36])[0]]
    huge += struct.pack("<IIII", 1793520001, 0, 0xFFFFFFF0, 0xFFFFFFF0) + b"\x00" * 64
    with open(os.path.join(OUT, "malformed_huge_record.pcap"), "wb") as fh:
        fh.write(huge)
    labels["malformed_huge_record.pcap"] = {"description": "Hostile input: a corrupt record claims to hold 4 GB.",
                                            "expected": [], "expect_partial": True}
    for name in labels:
        labels[name]["group"] = GROUPS.get(name, "Fault")
    print("broken_truncated.pcap, not_a_pcap.pcap, malformed_huge_record.pcap  (damaged / hostile inputs)")
    with open(os.path.join(OUT, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2)


if __name__ == "__main__":
    main()
