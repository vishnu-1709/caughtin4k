"""One entry point: analyze(path, options) -> Result. Also a sandboxed subprocess runner."""
from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .config import make_config
from .context import Context
from .detectors import all_detectors
from .explain import explain_all
from .findings import Finding, Incident
from .grouping import group
from .judge import judge_all
from .loader import CaptureError, ReadStats, iter_views, validate_file

VERDICT_ORDER = {"attack": 0, "fault": 1, "uncertain": 2}
CONF_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass
class Result:
    """Everything the UI, CLI and reports need. Contains no raw packet bytes."""

    file_name: str
    file_size: int
    file_format: str
    packets_read: int
    packets_skipped: int
    start: float
    end: float
    link_types: dict[str, int]
    findings: list[Finding]
    incidents: list[Incident]
    devices: list[dict[str, Any]]
    gateway_ip: str | None
    dns_servers: list[str]
    dhcp_servers: list[str]
    protocols: dict[str, int]
    top_talkers: list[tuple[str, int]]
    coverage: list[str]
    warnings: list[str]
    skipped_checks: list[str]
    frames: dict[int, tuple[float, str, str, str, str]]
    elapsed: float = 0.0
    partial: bool = False

    @property
    def duration(self) -> float:
        return max(0.0, self.end - self.start)

    def counts(self) -> dict[str, int]:
        out = {"attack": 0, "fault": 0, "uncertain": 0}
        for f in self.findings:
            out[f.verdict] = out.get(f.verdict, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["frames"] = {str(k): list(v) for k, v in self.frames.items()}
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Result":
        d = dict(d)
        d["findings"] = [Finding(**f) for f in d["findings"]]
        d["incidents"] = [Incident(**i) for i in d["incidents"]]
        d["frames"] = {int(k): tuple(v) for k, v in d["frames"].items()}
        d["top_talkers"] = [tuple(t) for t in d["top_talkers"]]
        return cls(**d)


def analyze(path: str, options: dict[str, Any] | None = None,
            progress: Callable[[int], None] | None = None) -> Result:
    """Run the full pipeline in-process. Raises CaptureError for user-facing problems."""
    options = options or {}
    cfg = make_config(options.get("config"))
    started = time.monotonic()
    fmt = validate_file(path, cfg["max_file_mb"])
    ctx = Context(cfg)
    detectors = all_detectors()
    stats = ReadStats()
    detector_errors: dict[str, int] = {}
    for v in iter_views(path, stats, cfg["max_packets"], cfg["max_seconds"]):
        ctx.feed(v)
        for det in detectors:
            try:
                det.feed(v, v.frame, v.ts, ctx)
            except Exception:  # one odd packet must never stop the analysis
                detector_errors[det.name] = detector_errors.get(det.name, 0) + 1
        if progress and v.frame % 1000 == 0:
            progress(v.frame)
    if stats.read == 0:
        raise CaptureError("broken" if (stats.truncated or stats.skipped) else "empty")
    ctx.finalize()

    findings: list[Finding] = []
    for det in detectors:
        try:
            findings.extend(det.finish(ctx))
        except Exception:
            detector_errors[det.name] = detector_errors.get(det.name, 0) + 1
    judge_all(findings, ctx)
    explain_all(findings, ctx)
    findings.sort(key=lambda f: (VERDICT_ORDER.get(f.verdict, 3), CONF_ORDER.get(f.confidence, 3), f.time_start))
    incidents = group(findings, ctx)

    warnings, coverage, skipped = _notes(ctx, stats, cfg, detector_errors)
    wanted = {n for f in findings for n in f.evidence_frames}
    frames = {n: ctx.rows[n] for n in sorted(wanted) if n in ctx.rows}
    return Result(
        file_name=os.path.basename(options.get("display_name") or path),
        file_size=os.path.getsize(path),
        file_format=fmt,
        packets_read=stats.read,
        packets_skipped=stats.skipped,
        start=ctx.start or 0.0,
        end=ctx.end or 0.0,
        link_types=dict(stats.linktypes),
        findings=findings,
        incidents=incidents,
        devices=ctx.devices(),
        gateway_ip=ctx.gateway_ip,
        dns_servers=[ip for ip, _ in ctx.dns_servers.most_common(10)],
        dhcp_servers=list(ctx.dhcp_servers)[:10],
        protocols=dict(ctx.protocols.most_common()),
        top_talkers=ctx.talkers.most_common(10),
        coverage=coverage,
        warnings=warnings,
        skipped_checks=skipped,
        frames=frames,
        elapsed=round(time.monotonic() - started, 2),
        partial=bool(stats.stopped_reason or stats.truncated),
    )


def _notes(ctx: Context, stats: ReadStats, cfg: dict[str, Any],
           detector_errors: dict[str, int]) -> tuple[list[str], list[str], list[str]]:
    """Warnings (something limited the analysis), coverage notes and skipped checks."""
    warnings: list[str] = []
    if stats.truncated:
        warnings.append("The file ends in the middle of a packet (damaged or cut short). "
                        "Everything before that point was analysed.")
    if stats.stopped_reason == "max_packets":
        warnings.append(f"Only the first {cfg['max_packets']:,} packets were analysed (safety limit).")
    if stats.stopped_reason == "max_seconds":
        warnings.append(f"Analysis stopped after {cfg['max_seconds']} seconds (safety limit); "
                        "results cover the first part of the capture.")
    if stats.skipped:
        warnings.append(f"{stats.skipped:,} packets could not be decoded and were skipped.")
    if ctx.flows_dropped:
        warnings.append(f"Too many connections to track; {ctx.flows_dropped:,} packets were not followed.")
    if ctx.ack_gaps >= 5:
        warnings.append(f"The capture seems to have missed packets ({ctx.ack_gaps} acknowledgements for data "
                        "that was never recorded). Packet-loss numbers may be off.")
    if detector_errors:
        warnings.append("Some packets were unusual and were ignored by: " + ", ".join(sorted(detector_errors)) + ".")

    coverage = ["This capture only shows traffic that passed the point where it was recorded. "
                "Problems elsewhere on the network may not be visible."]
    if ctx.midstream:
        coverage.append(f"{ctx.midstream:,} connections were already open when recording started; "
                        "their start is not visible.")
    skipped: list[str] = []
    has_arp = ctx.protocols.get("ARP", 0) > 0
    if not ctx.has_ethernet and not has_arp:
        skipped.append("ARP spoofing, duplicate IP and ARP conflict checks (no device/MAC information in "
                       "this capture type)")
        warnings.append("Some checks were skipped because this capture has no device (MAC) information.")
    elif not has_arp:
        coverage.append("No ARP traffic was recorded, so ARP spoofing and duplicate-IP checks had nothing to inspect.")
    if ctx.links.get("wifi"):
        coverage.append("Wi-Fi monitor capture: encrypted frames can't be read, only unencrypted ones were checked.")
    if not ctx.protocols.get("DNS"):
        coverage.append("No DNS traffic was recorded, so DNS failure and hijack checks had nothing to inspect.")
    if not ctx.protocols.get("DHCP"):
        coverage.append("No DHCP traffic was recorded (it only appears when a device joins the network), "
                        "so the rogue DHCP check had nothing to inspect.")
    coverage.extend(ctx.extra_notes)
    if ctx.protocols.get("IPv6"):
        coverage.append("IPv6-specific attacks (e.g. rogue router adverts) are not covered.")
    return warnings, coverage, skipped


# ----------------------------------------------------------------- sandboxing
def _limit_resources(memory_mb: int, cpu_seconds: int) -> Callable[[], None]:
    def apply() -> None:
        try:
            import resource
            mem = memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        except Exception:
            pass
    return apply


def analyze_safe(path: str, options: dict[str, Any] | None = None,
                 progress: Callable[[int], None] | None = None) -> Result:
    """Run analyze() in a separate, resource-limited process with a hard timeout.

    A hang or crash inside a packet dissector can then never freeze or take down the caller.
    """
    options = options or {}
    cfg = make_config(options.get("config"))
    validate_file(path, cfg["max_file_mb"])  # fail fast with a friendly message
    timeout = cfg["subprocess_timeout"]
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cmd = [sys.executable, "-I", os.path.join(root, "engine", "worker.py")]
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"}
    preexec = _limit_resources(cfg["memory_limit_mb"], timeout + 10) if os.name == "posix" else None
    proc = subprocess.Popen(cmd, cwd=root, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, preexec_fn=preexec)
    try:
        assert proc.stdin and proc.stdout and proc.stderr
        proc.stdin.write(json.dumps({"path": os.path.abspath(path), "options": options}).encode())
        proc.stdin.close()
        out, err_buf = bytearray(), bytearray()
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ, "out")
        sel.register(proc.stderr, selectors.EVENT_READ, "err")
        deadline = time.monotonic() + timeout
        open_pipes = 2
        while open_pipes:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureError("timeout")
            for key, _ in sel.select(timeout=min(0.5, remaining)):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    open_pipes -= 1
                    continue
                if key.data == "out":
                    out.extend(chunk)
                    if len(out) > 200 * 1024 * 1024:
                        raise CaptureError("internal")
                else:
                    err_buf.extend(chunk)
                    *lines, rest = err_buf.split(b"\n")
                    err_buf = bytearray(rest)
                    for line in lines:
                        if line.startswith(b"PROGRESS ") and progress:
                            try:
                                progress(int(line[9:]))
                            except ValueError:
                                pass
        proc.wait(timeout=5)
        try:
            payload = json.loads(out.decode() or "{}")
        except ValueError:
            raise CaptureError("internal") from None
        if "error" in payload:
            raise CaptureError(payload["error"], limit=int(cfg["max_file_mb"]))
        if "result" not in payload:
            raise CaptureError("internal")
        return Result.from_dict(payload["result"])
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
