"""Detector registry. Order does not matter: detectors are independent."""
from __future__ import annotations

from .arp import ArpDetector
from .base import Detector
from .delays import DelayDetector
from .dns_hijack import DnsHijackDetector
from .mtu import MtuDetector
from .dns_failures import DnsFailureDetector
from .port_scan import PortScanDetector
from .rogue_dhcp import RogueDhcpDetector
from .tcp_reset import TcpResetDetector
from .tcp_retrans import TcpRetransDetector


def all_detectors() -> list[Detector]:
    """Fresh instances of every detector."""
    return [ArpDetector(), PortScanDetector(), TcpResetDetector(), TcpRetransDetector(), DnsFailureDetector(),
            RogueDhcpDetector(), DnsHijackDetector(), DelayDetector(), MtuDetector()]
