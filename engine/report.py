"""Exports: JSON, evidence CSV and a self-contained HTML report. Every packet-derived value is escaped."""
from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .analyze import Result
from .checks import check_status

TOOL = "CaughtIn4K"
COLORS = {"attack": "#F04438", "fault": "#F79009", "uncertain": "#98A2B3", "healthy": "#12B76A"}
SEV = {"critical": "#F04438", "high": "#F79009", "medium": "#FDB022", "low": "#98A2B3"}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def to_json(result: Result) -> str:
    data: dict[str, Any] = {"tool": TOOL, "generated": _now(), **result.to_dict()}
    return json.dumps(data, indent=2, ensure_ascii=True)


def _csv_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (cells starting with = + - @ tab or CR)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def to_csv(result: Result) -> str:
    """One row per evidence packet: which finding it supports, and the packet summary."""
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["finding_id", "kind", "verdict", "frame", "time_s", "source", "destination", "protocol", "info"])
    for f in result.findings:
        for n in f.evidence_frames:
            row = result.frames.get(n)
            if not row:
                continue
            ts, src, dst, proto, info = row
            w.writerow([_csv_cell(v) for v in (f.id, f.kind, f.verdict, n, f"{max(ts - result.start, 0):.3f}",
                                                src, dst, proto, info)])
    return buf.getvalue()


def _e(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _code(value: Any) -> str:
    """Escape, then show `commands` as code."""
    return re.sub(r"`([^`]{1,200})`", r"<code>\1</code>", _e(value))


def _sev(level: str) -> str:
    c = SEV.get(level, SEV["low"])
    return f'<span class="sev" style="color:{c}; border-color:{c}">{_e(level)}</span>'


def _n(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def _list(items: list[str], ordered: bool = False) -> str:
    if not items:
        return "<p class='muted'>None found.</p>"
    tag = "ol" if ordered else "ul"
    return f"<{tag}>" + "".join(f"<li>{_code(i)}</li>" for i in items) + f"</{tag}>"


def to_html(result: Result) -> str:
    """A standalone, compact report: overview first, issues collapsed, background folded away.

    No JavaScript at all; a strict Content-Security-Policy blocks scripts even if escaping were bypassed.
    """
    c = result.counts()
    if c["attack"]:
        head, color = f"Under attack: {_n(c['attack'], 'attack')} found", COLORS["attack"]
    elif c["fault"] or c["uncertain"]:
        head, color = "Needs attention: problems found, no attacks", COLORS["fault"]
    else:
        head, color = "Network looks healthy", COLORS["healthy"]
    rank = {"attack": 0, "uncertain": 1, "fault": 2}
    ordered = sorted(result.findings, key=lambda f: (rank.get(f.verdict, 3),
                                                     ["critical", "high", "medium", "low"].index(f.severity)))
    attacks = [f for f in ordered if f.verdict == "attack"]
    if result.findings:
        story = (f"This capture shows {_n(len(result.findings), 'problem')}"
                 + (", all part of one connected incident." if len(result.incidents) == 1 and len(result.findings) > 1
                    else f" in {_n(len(result.incidents), 'separate incident')}."))
        if attacks:
            story += f" Most serious: {attacks[0].title_simple}."
    else:
        story = f"No faults or attacks were found in {result.packets_read:,} packets."
    first_steps = [(f, f.fix_steps[0]) for f in ordered[:3] if f.fix_steps]
    sev_counts = {s: sum(1 for f in result.findings if f.severity == s) for s in ("critical", "high", "medium", "low")}

    def tile(label: str, value: Any, tone: str = "") -> str:
        return f'<div class="tile" style="border-top-color:{tone or "#1F2A44"}"><b>{_e(value)}</b><span>{_e(label)}</span></div>'

    tiles = (tile("attacks", c["attack"], COLORS["attack"] if c["attack"] else "")
             + tile("faults", c["fault"], COLORS["fault"] if c["fault"] else "")
             + tile("uncertain", c["uncertain"], COLORS["uncertain"] if c["uncertain"] else "")
             + tile("incidents", len(result.incidents))
             + tile("packets", f"{result.packets_read:,}")
             + tile("seconds of traffic", f"{result.duration:.0f}"))
    do_first = "".join(
        f'<li><a href="#{_e(f.id)}">{_e(f.title_simple)}</a><br><span>{_code(step)}</span></li>' for f, step in first_steps)

    # ---- issues: one collapsed line each, two columns when opened
    issues = []
    for i, f in enumerate(ordered):
        rows = []
        for n in f.evidence_frames[:60]:
            r = result.frames.get(n)
            if r:
                rows.append("<tr>" + "".join(f"<td>{_e(v)}</td>" for v in
                                             (n, f"{max(r[0] - result.start, 0):.3f}", r[1], r[2], r[3], r[4])) + "</tr>")
        total = f.details.get("evidence_total", len(f.evidence_frames))
        fc = COLORS.get(f.verdict, COLORS["uncertain"])
        issues.append(f"""
<details class="issue" id="{_e(f.id)}" style="border-left-color:{fc}"{' open' if i == 0 else ''}>
<summary><span class="badge" style="background:{fc}">{_e(f.verdict.upper())}</span>{_sev(f.severity)}
<span class="ititle">{_e(f.title_simple)}</span>
<span class="imeta">{max(f.time_start - result.start, 0):.0f}s · {_e(f.confidence)} confidence · {len(f.evidence_frames)} packets</span></summary>
<div class="cols">
 <div>
  <h4>What happened</h4><p>{_code(f.explanation)}</p>
  {f'<p class="link">🔗 {_e(f.linked_text)}</p>' if f.linked_text else ''}
  <h4>What to do</h4>{_list(f.fix_steps, ordered=True)}
  <h4>Likely cause</h4><p>{_e(f.likely_cause)}</p>
 </div>
 <div class="why">
  <h4 class="bad">Signs of an attack</h4>{_list(f.indicators_for)}
  <h4 class="good">Signs of a harmless fault</h4>{_list(f.indicators_against)}
  <h4>Could it be harmless?</h4><p>{_e(f.benign_alternative)}</p>
 </div>
</div>
<div class="tech"><span class="muted">Technical:</span> <span class="mono">{_e(f.title_technical)}</span> ·
<span class="muted">Wireshark filter:</span> <code>{_e(f.wireshark_filter)}</code></div>
<details class="ev"><summary>Evidence packets ({len(rows)}{f' of {total}' if total > len(rows) else ''})</summary>
<div class="scroll"><table><tr><th>Frame</th><th>Time (s)</th><th>Source</th><th>Destination</th><th>Proto</th><th>Info</th></tr>
{''.join(rows)}</table></div></details>
</details>""")

    by_id = {f.id: f for f in result.findings}
    incidents = "".join(
        f'<div class="inc" style="border-left-color:{COLORS.get(i.verdict)}"><div>'
        f'<span class="badge" style="background:{COLORS.get(i.verdict)}">{_e(i.verdict.upper())}</span>{_sev(i.severity)}'
        f'<b>{_e(i.summary)}</b></div>'
        + (f'<p class="link">🔗 {_e(i.caused_by)}</p>' if i.caused_by else '')
        + _list(i.steps or [by_id[x].title_simple for x in i.finding_ids if x in by_id], ordered=True)
        + '</div>' for i in result.incidents)
    status_txt = {"clear": "clear", "no_data": "no data"}
    checks = "".join(
        f'<span class="pill"><i style="background:'
        f'{COLORS.get(x["verdict"], COLORS["uncertain"]) if x["status"] == "found" else ("#12B76A" if x["status"] == "clear" else "#475467")}'
        f'"></i>{_e(x["name"])} <em>{_e(str(x["count"]) + " found" if x["status"] == "found" else status_txt[x["status"]])}</em></span>'
        for x in check_status(result))
    notes = "".join(f"<li>{_e(w)}</li>" for w in result.warnings + result.coverage)
    meta = result.meta or {}
    start_utc = datetime.fromtimestamp(result.start, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if result.start else "-"
    facts = [("Report ID", (result.sha256 or "")[:12] or "-"), ("File", result.file_name),
             ("SHA-256", result.sha256 or "-"), ("Size", f"{result.file_size:,} bytes"),
             ("Format / link type", f"{result.file_format} / {', '.join(result.link_types) or 'unknown'}"),
             ("Packets", f"{result.packets_read:,} analysed, {result.packets_skipped:,} skipped"),
             ("Capture window", f"{start_utc}, {result.duration:.1f} s"),
             ("Analysed", f"{meta.get('analysed_at', _now())} in {result.elapsed:.2f} s"),
             ("Tool", meta.get("tool", f"{TOOL} {__version__}"))]
    facts_html = "".join(f'<tr><td>{_e(k)}</td><td class="mono" style="word-break:break-all">{_e(v)}</td></tr>'
                         for k, v in facts)
    protos = "".join(f"<tr><td>{_e(k)}</td><td>{v:,}</td><td>{v / max(result.packets_read, 1):.1%}</td></tr>"
                     for k, v in result.protocols.items())
    convs = "".join(f"<tr><td>{_e(cv['a'])}</td><td>{_e(cv['b'])}</td><td>{_e(cv['proto'])}</td><td>{cv['packets']:,}</td>"
                    f"<td>{cv['bytes']:,}</td><td>{cv['first']:.1f}s</td><td>{cv['duration']:.1f}s</td></tr>"
                    for cv in result.conversations[:15])
    talkers = "".join(f"<tr><td>{_e(ip)}</td><td>{b:,}</td></tr>" for ip, b in result.top_talkers)
    devices = "".join(f"<tr><td>{_e(d['ip'])}</td><td>{_e(d['mac'])}</td><td>{_e(d['vendor'])}</td>"
                      f"<td>{_e(d['role'] or '-')}</td><td>{_e(d['packets'])}</td></tr>" for d in result.devices[:200])
    sev_line = " · ".join(f"{_sev(s)} {n}" for s, n in sev_counts.items() if n)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL} report: {_e(result.file_name)}</title>
<style>
:root {{--bg:#0B1220; --card:#111A2E; --line:#1F2A44; --text:#E2E8F0; --muted:#94A3B8; --teal:#2DD4BF;}}
* {{box-sizing:border-box;}}
body {{background:var(--bg); color:var(--text); font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif; margin:0;}}
.wrap {{max-width:1100px; margin:0 auto; padding:0 18px 40px;}}
header.top {{display:flex; justify-content:space-between; align-items:baseline; flex-wrap:wrap; gap:8px; padding:18px 0 6px;}}
header.top h1 {{margin:0; font-size:1.5rem;}}
nav {{position:sticky; top:0; z-index:5; background:var(--bg); border-bottom:1px solid var(--line); padding:8px 0; margin-bottom:14px;}}
nav a {{color:var(--muted); margin-right:16px; font-size:0.9rem;}} nav a:hover {{color:var(--teal);}}
h2 {{font-size:1.1rem; margin:26px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line);}}
h2 .num {{display:inline-block; width:24px; height:24px; line-height:24px; text-align:center; border-radius:50%;
          background:var(--line); color:var(--teal); font-size:0.8rem; margin-right:8px;}}
h4 {{margin:12px 0 4px; font-size:0.82rem; text-transform:uppercase; letter-spacing:0.04em; color:var(--muted);}}
h4.bad {{color:#F97066;}} h4.good {{color:#32D583;}}
p {{margin:4px 0;}} ul, ol {{margin:4px 0; padding-left:1.25rem;}} li {{margin:2px 0;}}
a {{color:var(--teal); text-decoration:none;}}
.muted {{color:var(--muted);}} .link {{color:var(--teal);}}
.mono, code, td {{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:0.84rem;}}
code {{background:var(--bg); padding:1px 5px; border-radius:3px;}}
.badge {{color:#0B1220; font-weight:700; padding:2px 8px; border-radius:4px; font-size:0.72rem; margin-right:6px; letter-spacing:0.03em;}}
.sev {{border:1px solid; padding:1px 6px; border-radius:4px; font-size:0.7rem; font-weight:600; text-transform:uppercase; margin-right:8px;}}
.banner {{background:var(--card); border:1px solid var(--line); border-left:6px solid {color}; border-radius:8px; padding:14px 18px;}}
.banner h2 {{border:0; margin:0 0 4px; padding:0; color:{color}; font-size:1.4rem;}}
.tiles {{display:grid; grid-template-columns:repeat(6,1fr); gap:10px; margin:12px 0;}}
.tile {{background:var(--card); border:1px solid var(--line); border-top:3px solid; border-radius:8px; padding:10px 12px;}}
.tile b {{display:block; font-size:1.5rem;}} .tile span {{color:var(--muted); font-size:0.8rem;}}
.first {{background:var(--card); border:1px solid var(--teal); border-radius:8px; padding:12px 16px;}}
.first h3 {{margin:0 0 6px; font-size:0.95rem; color:var(--teal);}} .first li span {{color:var(--muted);}}
.issue {{background:var(--card); border:1px solid var(--line); border-left:6px solid; border-radius:8px; margin:8px 0;}}
.issue > summary {{cursor:pointer; padding:11px 14px; list-style:none; display:flex; flex-wrap:wrap; align-items:center; gap:4px;}}
.issue > summary::-webkit-details-marker {{display:none;}}
.issue > summary::before {{content:"▸"; color:var(--muted); margin-right:8px;}} .issue[open] > summary::before {{content:"▾";}}
.ititle {{font-weight:600; flex:1; min-width:260px;}} .imeta {{color:var(--muted); font-size:0.82rem;}}
.cols {{display:grid; grid-template-columns:1.1fr 1fr; gap:22px; padding:0 16px 6px; border-top:1px solid var(--line);}}
.why {{border-left:1px dashed var(--line); padding-left:18px;}}
.tech {{padding:8px 16px; border-top:1px solid var(--line); font-size:0.85rem;}}
.ev {{padding:0 16px 12px;}} .ev summary {{cursor:pointer; color:var(--teal); font-size:0.88rem; padding:6px 0;}}
.scroll {{max-height:260px; overflow:auto; border:1px solid var(--line); border-radius:6px;}}
table {{border-collapse:collapse; width:100%;}} th {{text-align:left; color:var(--muted); font-weight:600; font-size:0.8rem; position:sticky; top:0; background:var(--card);}}
td, th {{border-bottom:1px solid var(--line); padding:4px 8px; vertical-align:top;}}
.inc {{background:var(--card); border:1px solid var(--line); border-left:6px solid; border-radius:8px; padding:10px 14px; margin:8px 0;}}
.pill {{display:inline-block; border:1px solid var(--line); background:var(--card); border-radius:5px; padding:3px 9px; margin:3px 4px 3px 0; font-size:0.85rem;}}
.pill i {{display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px;}} .pill em {{color:var(--muted); font-style:normal;}}
details.more {{background:var(--card); border:1px solid var(--line); border-radius:8px; margin:8px 0; padding:0 14px;}}
details.more > summary {{cursor:pointer; padding:10px 0; font-weight:600;}}
.grid2 {{display:grid; grid-template-columns:1fr 1fr; gap:18px;}}
.kv td:first-child {{color:var(--muted); white-space:nowrap; font-family:inherit;}}
@media (max-width:760px) {{ .tiles {{grid-template-columns:repeat(3,1fr);}} .cols, .grid2 {{grid-template-columns:1fr;}} .why {{border:0; padding:0;}} }}
@media print {{
  body {{background:#fff; color:#111;}} nav {{display:none;}}
  .banner, .tile, .first, .issue, .inc, details.more, .pill {{background:#fff; border-color:#ccc;}}
  .muted, h4, .imeta, th {{color:#555;}} code {{background:#f3f3f3;}} .scroll {{max-height:none; overflow:visible;}}
  .issue, .inc {{break-inside:avoid;}}
}}
</style></head><body><div class="wrap">
<header class="top"><h1>{TOOL} report</h1>
<span class="muted">{_e(result.file_name)} · Report ID <span class="mono">{_e((result.sha256 or '')[:12] or '-')}</span> · {_now()}</span></header>
<nav><a href="#overview">Overview</a><a href="#issues">Issues ({len(result.findings)})</a><a href="#incidents">Incidents ({len(result.incidents)})</a>
<a href="#checks">What was checked</a><a href="#more">Traffic, devices &amp; details</a></nav>

<section id="overview">
<div class="banner"><h2>{_e(head)}</h2><p>{_e(story)}</p>{f'<p class="muted" style="margin-top:6px">Severity: {sev_line}</p>' if sev_line else ''}</div>
<div class="tiles">{tiles}</div>
{f'<div class="first"><h3>Do this first</h3><ol>{do_first}</ol></div>' if do_first else ''}
</section>

<h2 id="issues"><span class="num">1</span>Issues <span class="muted" style="font-weight:400; font-size:0.85rem">· most serious first · click a line to open or close it</span></h2>
{''.join(issues) or '<p class="muted">No issues found.</p>'}

<h2 id="incidents"><span class="num">2</span>Incidents <span class="muted" style="font-weight:400; font-size:0.85rem">· related issues as one story</span></h2>
{incidents or '<p class="muted">None.</p>'}

<h2 id="checks"><span class="num">3</span>What was checked</h2>
<div>{checks}</div>
<ul class="muted" style="margin-top:8px">{notes}</ul>

<h2 id="more"><span class="num">4</span>Traffic, devices &amp; details</h2>
<details class="more"><summary>Traffic: protocols, top talkers, largest conversations</summary>
<div class="grid2"><div><table><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>{protos}</table></div>
<div><table><tr><th>Address</th><th>Bytes sent</th></tr>{talkers}</table></div></div>
<h4>Largest conversations</h4><div class="scroll"><table><tr><th>Endpoint A</th><th>Endpoint B</th><th>Proto</th><th>Packets</th><th>Bytes</th><th>Starts</th><th>Duration</th></tr>{convs}</table></div><p></p>
</details>
<details class="more"><summary>Devices ({len(result.devices)})</summary>
<div class="scroll"><table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Role</th><th>Packets</th></tr>{devices}</table></div><p></p>
</details>
<details class="more"><summary>Capture details and file fingerprint (SHA-256)</summary>
<table class="kv">{facts_html}</table>
<p class="muted">The SHA-256 fingerprint identifies exactly which file this report describes (check with <code>sha256sum</code>
or <code>Get-FileHash</code>).</p>
</details>
<details class="more"><summary>How the verdicts were reached</summary>
<p><b>Attack, fault or uncertain.</b> Each check collects facts from the packets. A judge weighs explicit signs of an
attack against signs of a harmless fault (both are listed on every issue). "Attack" needs strong evidence that clearly
beats the harmless explanation; mixed evidence is "uncertain", and the advice then starts with checks, not drastic action.</p>
<p><b>Severity</b>: <i>critical</i> = traffic can be read or redirected · <i>high</i> = outage or exposure for several users ·
<i>medium</i> = degraded service · <i>low</i> = minor.</p>
<p><b>Limits.</b> A capture only shows traffic that passed where it was recorded; encrypted traffic hides some details;
findings are evidence-based indicators, not legal proof. All detection logic is CaughtIn4K's own; Scapy was used only
to read packets. No network connections were made during analysis.</p><p></p>
</details>
<p class="muted" style="margin-top:20px">Printing: open the sections you want on paper first (closed sections are not printed).</p>
</div></body></html>"""


_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(name: str, suffix: str) -> str:
    """A download/output file name with no directories or odd characters."""
    stem = _SAFE.sub("_", os.path.splitext(os.path.basename(name))[0])[:60].strip("._") or "capture"
    return f"caughtin4k-{stem}{suffix}"


def safe_output_path(path: str, allowed_ext: tuple[str, ...], base_dir: str | None = None) -> str:
    """Resolve an output path and refuse anything outside base_dir (no path traversal) or with another extension."""
    base = os.path.realpath(base_dir or os.getcwd())
    full = os.path.realpath(os.path.join(base, path))
    if os.path.commonpath([base, full]) != base:
        raise ValueError("Output path must be inside the current folder.")
    if not full.lower().endswith(allowed_ext):
        raise ValueError(f"Output file must end with {' or '.join(allowed_ext)}.")
    if os.path.isdir(full):
        raise ValueError("Output path is a folder.")
    return full
