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
                    seg_size: int = 1400, sport: int | None = None, close: bool = True) -> float:
        """Full HTTPS-like conversation. Returns the end time.

        retrans: indices of server data segments that are lost once and re-sent.
        """
        rng = self.rng
        sport = sport or rng.randint(49152, 65000)
        local = server_ip.startswith("192.168.")
        srv_mac = server_mac or (GW[1] if not local else server_mac)
        c_dst = client_l2_dst or srv_mac
        ttl_s = 64 if local else rng.choice([52, 54, 57, 116])
        cseq, sseq = rng.randint(1, 2**31), rng.randint(1, 2**31)

        def c2s(tt: float, flags: str, payload: bytes = b"") -> None:
            nonlocal cseq
            p = Ether(src=client[1], dst=c_dst) / IP(src=client[0], dst=server_ip, ttl=64, flags="DF") / \
                TCP(sport=sport, dport=dport, flags=flags, seq=cseq, ack=sseq, window=64240)
            self.add(tt, p / Raw(payload) if payload else p)
            cseq += len(payload) + (1 if ("S" in flags or "F" in flags) else 0)

        def s2c(tt: float, flags: str, payload: bytes = b"", seq: int | None = None) -> None:
            nonlocal sseq
            use = sseq if seq is None else seq
            p = Ether(src=srv_mac, dst=client[1]) / IP(src=server_ip, dst=client[0], ttl=ttl_s, flags="DF") / \
                TCP(sport=dport, dport=sport, flags=flags, seq=use, ack=cseq, window=65535)
            self.add(tt, p / Raw(payload) if payload else p)
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
        net.tcp_session(t, victim, SITES[name], client_l2_dst=ATTACKER[1], rtt=0.09, segments=3)
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


SCENARIOS: dict[str, tuple[Callable[[], Net], str, list[dict]]] = {
    "clean.pcap": (clean, "A normal two-minute office capture with no problems.", []),
    "arp_spoof.pcap": (arp_spoof, "A device pretends to be the router to intercept a laptop's traffic.",
                       [{"kind": "arp_spoofing", "verdict": "attack"}]),
    "duplicate_ip.pcap": (duplicate_ip, "Two devices were given the same IP address by mistake.",
                          [{"kind": "duplicate_ip", "verdict": "fault"}]),
}


def main() -> None:
    os.makedirs(OUT, exist_ok=True)
    labels = {}
    for name, (build, description, expected) in SCENARIOS.items():
        net = build()
        net.write(name)
        labels[name] = {"description": description, "expected": expected}
        print(f"{name:32} {len(net.pkts):5} packets  {description}")
    with open(os.path.join(OUT, "labels.json"), "w") as fh:
        json.dump(labels, fh, indent=2)


if __name__ == "__main__":
    main()
