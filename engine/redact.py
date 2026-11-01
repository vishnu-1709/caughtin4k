"""Consistent masking of IP and MAC addresses (same real value -> same mask everywhere)."""
from __future__ import annotations

import re
from typing import Any

IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\w|\.\d)")
MAC = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?!\w|:[0-9a-fA-F])")
KEEP = {"0.0.0.0", "255.255.255.255", "ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}


class Redactor:
    """Replaces addresses with stable tokens like 'IP-3' and 'MAC-1'."""

    def __init__(self) -> None:
        self.ips: dict[str, str] = {}
        self.macs: dict[str, str] = {}

    def _ip(self, m: re.Match) -> str:
        v = m.group(0)
        if v in KEEP:
            return v
        return self.ips.setdefault(v, f"IP-{len(self.ips) + 1}")

    def _mac(self, m: re.Match) -> str:
        v = m.group(0).lower()
        if v in KEEP:
            return v
        return self.macs.setdefault(v, f"MAC-{len(self.macs) + 1}")

    def text(self, s: str) -> str:
        return IPV4.sub(self._ip, MAC.sub(self._mac, s))

    def apply(self, obj: Any) -> Any:
        """Redact every string (and dict key) inside a JSON-like structure."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, dict):
            return {self.apply(k) if isinstance(k, str) else k: self.apply(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            out = [self.apply(v) for v in obj]
            return type(obj)(out) if isinstance(obj, tuple) else out
        return obj


def redact_result(result: Any) -> Any:
    """Return a redacted copy of an analyze.Result."""
    from .analyze import Result

    return Result.from_dict(Redactor().apply(result.to_dict()))
