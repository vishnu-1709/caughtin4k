"""Safe capture loading: validate before parsing, stream packets, never crash on bad input."""
from __future__ import annotations

import logging
import os
import re
import stat
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

logging.getLogger("scapy").setLevel(logging.CRITICAL)

from scapy.config import conf  # noqa: E402
from scapy.layers.dhcp import BOOTP, DHCP  # noqa: E402
from scapy.layers.dns import DNS  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP, IPerror, TCPerror, UDPerror  # noqa: E402
from scapy.layers.inet6 import IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.utils import RawPcapNgReader, RawPcapReader  # noqa: E402

conf.verb = 0

PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "pcap",
    b"\xa1\xb2\xc3\xd4": "pcap",
    b"\x4d\x3c\xb2\xa1": "pcap (ns)",
    b"\xa1\xb2\x3c\x4d": "pcap (ns)",
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

# Link types (DLT values) and how much device information they carry.
LINKTYPES = {
    1: "ethernet",
    101: "raw_ip",
    228: "raw_ip",
    229: "raw_ip",
    12: "raw_ip",
    14: "raw_ip",
    0: "loopback",
    108: "loopback",
    113: "cooked",
    276: "cooked",
    105: "wifi",
    127: "wifi",
    192: "wifi",
}

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
# ports whose payload start is kept (bounded) so the clear-text login check can inspect it
LOGIN_PORTS = {21, 23, 25, 80, 110, 143, 587, 8080}

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


class CaptureError(Exception):
    """A user-facing problem with the input file. `code` drives the UI message."""

    MESSAGES = {
        "not_found": "The file could not be found.",
        "not_file": "That path is not a regular file.",
        "empty": "This capture has no packets.",
        "too_big": "This file is over {limit} MB. Record a shorter capture, or run CaughtIn4K "
        "locally for bigger files.",
        "not_pcap": "This isn't a packet capture (.pcap or .pcapng). Try a sample instead.",
        "broken": "This capture is damaged and could not be read at all.",
        "timeout": "Reading this capture took too long and was stopped. Try a shorter capture.",
        "internal": "Something went wrong while analysing this capture. No data was kept.",
        "busy": "The server is busy analysing other captures. Please try again in a minute.",
        "rate": "Too many analyses in a short time. Please wait a minute and try again.",
    }

    def __init__(self, code: str, **fmt: Any) -> None:
        self.code = code
        self.message = self.MESSAGES.get(code, self.MESSAGES["internal"]).format(**fmt)
        super().__init__(self.message)


def clean_text(value: Any, limit: int = 255) -> str:
    """Decode packet text safely: no control characters, bounded length."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = _CONTROL.sub("?", str(value))
    return text[:limit]


def validate_file(path: str, max_mb: float) -> str:
    """Check the file before any parsing. Returns the format name or raises CaptureError."""
    real = os.path.realpath(path)
    try:
        st = os.stat(real)
    except OSError:
        raise CaptureError("not_found") from None
    if not stat.S_ISREG(st.st_mode):
        raise CaptureError("not_file")
    if st.st_size > max_mb * 1024 * 1024:
        raise CaptureError("too_big", limit=int(max_mb))
    if st.st_size == 0:
        raise CaptureError("empty")
    with open(real, "rb") as fh:
        magic = fh.read(4)
    if magic in PCAP_MAGICS:
        if st.st_size < 24:
            raise CaptureError("broken")
        if st.st_size == 24:
            raise CaptureError("empty")
        return PCAP_MAGICS[magic]
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError("not_pcap")


@dataclass
class ReadStats:
    """Counters the reader fills in while streaming."""

    read: int = 0
    skipped: int = 0
    truncated: bool = False
    stopped_reason: str = ""  # "", "max_packets", "max_seconds"
    linktypes: dict[str, int] = field(default_factory=dict)


def _layer_class(linktype: int) -> Any:
    return conf.l2types.num2layer.get(linktype, conf.raw_layer)


def iter_raw(path: str, stats: ReadStats) -> Iterator[tuple[bytes, float, int, int]]:
    """Yield (data, timestamp, wirelen, linktype) records; stops cleanly on damage."""
    try:
        reader = RawPcapReader(path)
    except Exception:
        raise CaptureError("broken") from None
    is_ng = isinstance(reader, RawPcapNgReader)
    size = os.path.getsize(path)
    try:
        while True:
            try:
                rec = reader._read_packet()  # scapy bounds each read against huge caplen values
            except EOFError:
                break
            except Exception:
                stats.truncated = True
                break
            if rec is None:
                continue
            data, meta = rec
            if is_ng:
                if meta.tshigh is None:
                    ts = 0.0
                else:
                    ts = float(((meta.tshigh << 32) + meta.tslow) / meta.tsresol)
                yield data, ts, meta.wirelen or len(data), meta.linktype
            else:
                if len(data) < meta.caplen:
                    stats.truncated = True
                frac = 1e9 if reader.nano else 1e6
                yield data, meta.sec + meta.usec / frac, meta.wirelen, reader.linktype
        try:
            if reader.f.tell() < size:
                stats.truncated = True
        except Exception:
            pass
    finally:
        try:
            reader.close()
        except Exception:
            pass


def iter_views(path: str, stats: ReadStats, max_packets: int, max_seconds: float) -> Iterator["PacketView"]:
    """Stream PacketViews with caps. Bad packets are counted and skipped, never raised."""
    started = time.monotonic()
    frame = 0
    for data, ts, wirelen, linktype in iter_raw(path, stats):
        frame += 1
        if frame > max_packets:
            stats.stopped_reason = "max_packets"
            break
        if frame % 500 == 0 and time.monotonic() - started > max_seconds:
            stats.stopped_reason = "max_seconds"
            break
        kind = LINKTYPES.get(linktype, "other")
        stats.linktypes[kind] = stats.linktypes.get(kind, 0) + 1
        try:
            pkt = _layer_class(linktype)(data)
            view = PacketView(pkt, frame, ts, wirelen, kind)
        except Exception:
            stats.skipped += 1
            continue
        stats.read += 1
        yield view


def quick_preview(path: str, max_mb: float, max_seconds: float = 5.0) -> dict[str, Any]:
    """Count packets and duration without dissecting (fast). Raises CaptureError."""
    fmt = validate_file(path, max_mb)
    stats = ReadStats()
    count, first, last = 0, None, None
    started = time.monotonic()
    for _data, ts, _wl, _lt in iter_raw(path, stats):
        count += 1
        first = ts if first is None else first
        last = ts
        if count % 2000 == 0 and time.monotonic() - started > max_seconds:
            stats.stopped_reason = "max_seconds"
            break
    if count == 0:
        raise CaptureError("broken" if stats.truncated else "empty")
    return {
        "format": fmt,
        "size": os.path.getsize(path),
        "packets": count,
        "packets_estimate": bool(stats.stopped_reason),
        "duration": max(0.0, (last or 0) - (first or 0)),
        "truncated": stats.truncated,
    }


def _mac(value: Any) -> str | None:
    if not value:
        return None
    text = str(value).lower()
    return text if len(text) == 17 else None


class PacketView:
    """Pre-parsed, read-only view of one packet so detectors never re-dissect."""

    __slots__ = (
        "frame", "ts", "length", "link", "eth_src", "eth_dst", "arp",
        "ip_ver", "ip_src", "ip_dst", "ttl", "ip_df", "ip_len",
        "tcp", "udp", "dns", "dhcp", "icmp", "proto", "payload",
    )

    def __init__(self, pkt: Any, frame: int, ts: float, wirelen: int, link: str) -> None:
        self.frame, self.ts, self.length, self.link = frame, ts, wirelen or len(pkt), link
        self.eth_src = self.eth_dst = None
        self.arp = self.tcp = self.udp = self.dns = self.dhcp = self.icmp = None
        self.payload: bytes = b""
        self.ip_ver = 0
        self.ip_src = self.ip_dst = None
        self.ttl = self.ip_len = 0
        self.ip_df = False
        self.proto = "Other"

        eth = pkt.getlayer(Ether)
        if eth is not None:
            self.eth_src, self.eth_dst = _mac(eth.src), _mac(eth.dst)

        arp = pkt.getlayer(ARP)
        if arp is not None:
            self.arp = (int(arp.op), _mac(arp.hwsrc), str(arp.psrc), _mac(arp.hwdst), str(arp.pdst))
            self.proto = "ARP"
            return

        ip = pkt.getlayer(IP)
        l4_owner = ip
        if ip is not None and not isinstance(ip, IPerror):
            self.ip_ver, self.ip_src, self.ip_dst = 4, str(ip.src), str(ip.dst)
            self.ttl, self.ip_len = int(ip.ttl), int(ip.len or 0)
            self.ip_df = bool(int(ip.flags) & 0x2)
            self.proto = "IPv4"
            header = int(ip.ihl or 5) * 4
            ip_payload = self.ip_len - header
        else:
            ip6 = pkt.getlayer(IPv6)
            if ip6 is None:
                return
            l4_owner = ip6
            self.ip_ver, self.ip_src, self.ip_dst = 6, str(ip6.src), str(ip6.dst)
            self.ttl, self.ip_len = int(ip6.hlim), int(ip6.plen or 0) + 40
            self.proto = "IPv6"
            ip_payload = int(ip6.plen or 0)

        tcp = l4_owner.getlayer(TCP)
        if tcp is not None and not isinstance(tcp, TCPerror):
            plen = max(0, ip_payload - int(tcp.dataofs or 5) * 4)
            self.tcp = (int(tcp.sport), int(tcp.dport), int(tcp.flags), int(tcp.seq), int(tcp.ack),
                        int(tcp.window), plen)
            self.proto = "TCP"
            if plen and (self.tcp[0] in LOGIN_PORTS or self.tcp[1] in LOGIN_PORTS):
                self.payload = bytes(tcp.payload)[:600]
        udp = l4_owner.getlayer(UDP)
        if udp is not None and not isinstance(udp, UDPerror):
            self.udp = (int(udp.sport), int(udp.dport), max(0, int(udp.len or 8) - 8))
            self.proto = "UDP"
            dns = udp.getlayer(DNS)
            if dns is not None and 53 in (self.udp[0], self.udp[1]):
                self.dns = _parse_dns(dns)
                if self.dns is not None:
                    self.proto = "DNS"
            bootp = udp.getlayer(BOOTP)
            if bootp is not None and {self.udp[0], self.udp[1]} & {67, 68}:
                self.dhcp = _parse_dhcp(bootp, udp.getlayer(DHCP))
                self.proto = "DHCP"
        icmp = pkt.getlayer(ICMP)
        if icmp is not None and self.ip_ver == 4:
            inner = icmp.getlayer(IPerror)
            inner_info = None
            if inner is not None:
                inner_tcp = inner.getlayer(TCPerror)
                inner_info = (str(inner.src), str(inner.dst), int(inner.len or 0), bool(int(inner.flags) & 0x2),
                              int(inner_tcp.sport) if inner_tcp is not None else None,
                              int(inner_tcp.dport) if inner_tcp is not None else None)
            mtu = int(icmp.nexthopmtu or 0) if int(icmp.type) == 3 and int(icmp.code) == 4 else 0
            self.icmp = (int(icmp.type), int(icmp.code), mtu, inner_info)
            self.proto = "ICMP"


def _parse_dns(dns: Any) -> dict[str, Any] | None:
    """Extract the DNS fields detectors need; bounded and cleaned."""
    try:
        qname, qtype = "", 0
        if dns.qd:
            q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
            qname = clean_text(q.qname).rstrip(".").lower()
            qtype = int(q.qtype)
        answers = []
        for rr in list(dns.an or [])[:20]:
            rtype = int(getattr(rr, "type", 0))
            rdata = getattr(rr, "rdata", "")
            if isinstance(rdata, list):
                rdata = rdata[0] if rdata else ""
            answers.append((clean_text(getattr(rr, "rrname", b"")).rstrip(".").lower(), rtype,
                            clean_text(rdata).rstrip("."), int(getattr(rr, "ttl", 0) or 0)))
        return {"id": int(dns.id), "qr": int(dns.qr), "rcode": int(dns.rcode),
                "qname": qname, "qtype": qtype, "answers": answers}
    except Exception:
        return None


def _parse_dhcp(bootp: Any, dhcp: Any) -> dict[str, Any] | None:
    """Extract BOOTP/DHCP fields: message type, server id, router and DNS options."""
    info: dict[str, Any] = {
        "op": int(bootp.op), "yiaddr": str(bootp.yiaddr), "xid": int(bootp.xid),
        "chaddr": _mac(":".join(f"{b:02x}" for b in bytes(bootp.chaddr)[:6])),
        "type": 0, "server_id": None, "router": [], "dns": [], "lease": None,
    }
    if dhcp is None:
        return info
    for opt in dhcp.options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        name, values = opt[0], [str(v) for v in opt[1:]]
        if name == "message-type":
            info["type"] = int(opt[1])
        elif name == "server_id":
            info["server_id"] = values[0]
        elif name == "router":
            info["router"] = values
        elif name == "name_server":
            info["dns"] = values
        elif name == "lease_time":
            info["lease"] = int(opt[1])
    return info


def flags_text(flags: int) -> str:
    names = [(SYN, "SYN"), (ACK, "ACK"), (FIN, "FIN"), (RST, "RST"), (PSH, "PSH")]
    return ",".join(n for bit, n in names if flags & bit) or "none"
