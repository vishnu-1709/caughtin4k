"""Clear-text credentials: logins sent without encryption (FTP, Telnet, POP3, IMAP, SMTP, HTTP).

Privacy: the password is never stored. Usernames are masked before they leave this module.
"""
from __future__ import annotations

import base64
import re
from typing import Any

from ..context import Context
from ..findings import Finding
from ..loader import PacketView
from .base import Detector

PROTOCOLS = {21: "FTP", 23: "Telnet", 25: "SMTP", 587: "SMTP", 110: "POP3", 143: "IMAP", 80: "HTTP", 8080: "HTTP"}
USER_CMD = re.compile(rb"^(?:USER|user)\s+(\S{1,64})")
PASS_CMD = re.compile(rb"^(?:PASS|pass)\s+\S")
IMAP_LOGIN = re.compile(rb"^\S+\s+LOGIN\s+\"?([^\s\"]{1,64})\"?\s+\S", re.I)
SMTP_AUTH = re.compile(rb"^AUTH\s+(PLAIN|LOGIN)", re.I)
HTTP_BASIC = re.compile(rb"\r\nAuthorization:\s*Basic\s+([A-Za-z0-9+/=]{4,200})", re.I)
HTTP_FORM = re.compile(rb"(?:^|&)(?:pass|passwd|password|pwd)=[^&\s]", re.I)
HTTP_FORM_USER = re.compile(rb"(?:^|&)(?:user|username|login|email)=([^&\s]{1,64})", re.I)


def mask(user: str) -> str:
    """'alice' -> 'a***e'. Never reveal a full username."""
    user = user.strip()
    if len(user) <= 2:
        return "*" * len(user) or "?"
    return f"{user[0]}***{user[-1]}"


class CleartextDetector(Detector):
    name = "cleartext"

    def __init__(self) -> None:
        super().__init__()
        self.hits: dict[tuple[str, str, str], dict[str, Any]] = {}  # (client, server, proto) -> stats

    def feed(self, pkt: PacketView, frame_no: int, ts: float, ctx: Context) -> None:
        if not pkt.payload or not pkt.tcp:
            return
        sport, dport = pkt.tcp[0], pkt.tcp[1]
        if dport not in PROTOCOLS:
            return  # only client -> server direction carries the login
        proto = PROTOCOLS[dport]
        data = pkt.payload
        user, has_secret = None, False
        if proto in ("FTP", "POP3"):
            m = USER_CMD.match(data)
            if m:
                user = m.group(1).decode("utf-8", "replace")
            has_secret = bool(PASS_CMD.match(data))
        elif proto == "IMAP":
            m = IMAP_LOGIN.match(data)
            if m:
                user, has_secret = m.group(1).decode("utf-8", "replace"), True
        elif proto == "SMTP":
            has_secret = bool(SMTP_AUTH.match(data))
        elif proto == "Telnet":
            return  # keystrokes are split across packets; not decoded reliably
        elif proto == "HTTP":
            m = HTTP_BASIC.search(data)
            if m:
                try:
                    decoded = base64.b64decode(m.group(1), validate=True).decode("utf-8", "replace")
                    user, has_secret = decoded.split(":", 1)[0], ":" in decoded
                except ValueError:
                    pass
            elif HTTP_FORM.search(data.split(b"\r\n\r\n", 1)[-1]):
                body = data.split(b"\r\n\r\n", 1)[-1]
                mu = HTTP_FORM_USER.search(body)
                user, has_secret = (mu.group(1).decode("utf-8", "replace") if mu else None), True
        if not (user or has_secret):
            return
        key = (pkt.ip_src, pkt.ip_dst, proto)
        if key not in self.hits and len(self.hits) >= 500:
            return
        h = self.hits.setdefault(key, {"users": set(), "secrets": 0, "first": ts, "last": ts, "frames": [],
                                       "port": dport})
        h["last"] = ts
        if user and len(h["users"]) < 10:
            h["users"].add(mask(user))
        h["secrets"] += int(has_secret)
        if len(h["frames"]) < 20:
            h["frames"].append(frame_no)
            # evidence row never contains the payload itself
            ctx.remember(pkt, info=f"{proto} login data sent unencrypted (content hidden)")

    def finish(self, ctx: Context) -> list[Finding]:
        findings = []
        for (client, server, proto), h in self.hits.items():
            if not h["secrets"]:
                continue  # a username alone is not a credential leak
            f = Finding(
                id=self.new_id(), kind="cleartext_credentials", category="fault", hosts=[client, server],
                time_start=h["first"], time_end=h["last"],
                wireshark_filter=f"ip.addr == {client} && ip.addr == {server} && tcp.port == {h['port']}",
                details={"client": client, "server": server, "protocol": proto, "port": h["port"],
                         "users": sorted(h["users"]), "logins": h["secrets"]},
            )
            f.add_evidence(h["frames"])
            findings.append(f)
        return findings
