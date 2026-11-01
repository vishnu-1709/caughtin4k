"""Detector registry. Order does not matter: detectors are independent."""
from __future__ import annotations

from .arp import ArpDetector
from .base import Detector


def all_detectors() -> list[Detector]:
    """Fresh instances of every detector."""
    return [ArpDetector()]
