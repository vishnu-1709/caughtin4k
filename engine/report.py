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
    """A standalone report. A strict Content-Security-Policy blocks scripts even if escaping were bypassed."""
    c = result.counts()
    if c["attack"]:
        head, color = f"Under attack: {_n(c['attack'], 'attack')}, {_n(c['fault'], 'fault')}", COLORS["attack"]
    elif c["fault"] or c["uncertain"]:
        head, color = f"Needs attention: {_n(c['fault'], 'fault')}, {c['uncertain']} uncertain", COLORS["fault"]
    else:
        head, color = "Network looks healthy", COLORS["healthy"]
    cards = []
    # --- summary: what happened, what to do first, what was checked
    attacks = [f for f in result.findings if f.verdict == "attack"]
    others = [f for f in result.findings if f.verdict != "attack"]
    if result.findings:
        story = (f"This capture shows {_n(len(result.findings), 'problem')}"
                 + (", all part of one connected incident. " if len(result.incidents) == 1 and len(result.findings) > 1
                    else f" in {_n(len(result.incidents), 'separate incident')}. "))
        if attacks:
            story += f"The most important is an attack: {attacks[0].title_simple}. "
        for inc in result.incidents:
            if inc.caused_by:
                story += f"Linked: {inc.caused_by}. "
    else:
        story = (f"No faults or attacks were found in {result.packets_read:,} packets. "
                 "The checklist below shows what was examined.")
    first_steps = [f"{f.title_simple}: {f.fix_steps[0]}" for f in (attacks + others)[:3] if f.fix_steps]
    toc = "".join(
        f'<tr><td><a href="#{_e(f.id)}">{_e(f.id)}</a></td>'
        f'<td><span class="badge" style="background:{COLORS.get(f.verdict)}">{_e(f.verdict.upper())}</span></td>'
        f'<td>{_sev(f.severity)}</td><td>{_e(f.confidence)}</td><td><a href="#{_e(f.id)}">{_e(f.title_simple)}</a></td>'
        f'<td>{max(f.time_start - result.start, 0):.0f}s</td><td>{len(f.evidence_frames)}</td></tr>'
        for f in result.findings)
    status_txt = {"clear": "Clear", "no_data": "No data in this capture"}
    checks = "".join(
        f"<tr><td>{_e(c['name'])}</td><td>{_e(c['category'])}</td><td style='color:"
        f"{COLORS.get(c['verdict'], COLORS['healthy']) if c['status'] != 'no_data' else '#94A3B8'}'>"
        f"{_e(str(c['count']) + ' found' if c['status'] == 'found' else status_txt[c['status']])}</td></tr>"
        for c in check_status(result))
    summary = (f'<section class="card"><h2>Summary</h2><p>{_e(story)}</p>'
               + (f'<h3>Do this first</h3>{_list(first_steps, ordered=True)}' if first_steps else '')
               + (f'<h3>Issues in this report</h3><table class="plain"><tr><th>ID</th><th>Verdict</th><th>Severity</th>'
                  f'<th>Confidence</th><th>Issue</th><th>Starts</th><th>Evidence</th></tr>{toc}</table>' if toc else '')
               + f'<h3>What was checked</h3><table class="plain"><tr><th>Check</th><th>Type</th><th>Result</th></tr>{checks}</table>'
               + '</section>')
    for f in result.findings:
        rows = []
        for n in f.evidence_frames[:200]:
            r = result.frames.get(n)
            if r:
                rows.append("<tr>" + "".join(f"<td>{_e(v)}</td>" for v in
                                             (n, f"{max(r[0] - result.start, 0):.3f}", r[1], r[2], r[3], r[4])) + "</tr>")
        fc = COLORS.get(f.verdict, COLORS["uncertain"])
        cards.append(f"""
<section class="card" id="{_e(f.id)}">
  <div><span class="badge" style="background:{fc}">{_e(f.verdict.upper())}</span> {_sev(f.severity)}
  <span class="muted">{_e(f.id)} · {_e(f.confidence)} confidence · {max(f.time_start - result.start, 0):.1f}s – {max(f.time_end - result.start, 0):.1f}s · {_e(f.kind)}</span></div>
  <h2>{_e(f.title_simple)}</h2>
  <p class="muted mono">{_e(f.title_technical)}</p>
  <p>{_code(f.explanation)}</p>
  <p class="muted">{_code(f.explanation_technical)}</p>
  {f'<p class="link">{_e(f.linked_text)}</p>' if f.linked_text else ''}
  <h3>What to do</h3>{_list(f.fix_steps, ordered=True)}
  <h3>Likely cause</h3><p>{_e(f.likely_cause)}</p>
  <h3>Signs of an attack</h3>{_list(f.indicators_for)}
  <h3>Signs of a harmless fault</h3>{_list(f.indicators_against)}
  <h3>Could it be harmless?</h3><p>{_e(f.benign_alternative)}</p>
  <h3>Wireshark filter</h3><pre>{_e(f.wireshark_filter)}</pre>
  <details><summary>Evidence ({len(rows)} packets)</summary>
  <table><tr><th>Frame</th><th>Time (s)</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Info</th></tr>
  {''.join(rows)}</table></details>
</section>""")
    notes = "".join(f"<li>{_e(w)}</li>" for w in result.warnings + result.coverage)
    by_id = {f.id: f for f in result.findings}
    incidents = "".join(
        f'<section class="card"><div><span class="badge" style="background:{COLORS.get(i.verdict)}">'
        f'{_e(i.verdict.upper())}</span> {_sev(i.severity)} <span class="muted">{_e(i.id)} · '
        f'{_n(len(i.finding_ids), "issue")}</span></div><h3 style="color:#E2E8F0">{_e(i.summary)}</h3>'
        + (f'<p class="link">{_e(i.caused_by)}</p>' if i.caused_by else '')
        + _list(i.steps or [by_id[x].title_simple for x in i.finding_ids if x in by_id], ordered=True)
        + '</section>' for i in result.incidents)
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
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{TOOL} report: {_e(result.file_name)}</title>
<style>
body {{background:#0B1220; color:#E2E8F0; font-family:system-ui,sans-serif; max-width:1000px; margin:2rem auto; padding:0 1rem;}}
.card {{background:#111A2E; border:1px solid #1F2A44; border-radius:6px; padding:1rem 1.2rem; margin:1rem 0;}}
.banner {{border-left:6px solid {color}; background:#111A2E; padding:0.8rem 1rem; border-radius:6px;}}
.badge {{color:#0B1220; font-weight:700; padding:2px 8px; border-radius:4px; font-size:0.8rem;}}
.muted {{color:#94A3B8;}} .link {{color:#2DD4BF;}}
.mono, pre, td {{font-family:ui-monospace,Menlo,Consolas,monospace; font-size:0.85rem;}}
pre {{background:#0B1220; padding:0.5rem; border-radius:4px; white-space:pre-wrap;}}
table {{border-collapse:collapse; width:100%;}} td, th {{border-bottom:1px solid #1F2A44; padding:3px 6px; text-align:left;}}
h2 {{margin:0.4rem 0 0.2rem 0;}} h3 {{font-size:0.95rem; color:#94A3B8; margin-bottom:0.2rem;}}
a {{color:#2DD4BF; text-decoration:none;}} table.plain td {{font-family:inherit; font-size:0.9rem;}}
.grid {{display:grid; grid-template-columns:1fr 1fr; gap:1.5rem;}} .kv td:first-child {{color:#94A3B8; white-space:nowrap; font-family:inherit;}}
.sev {{border:1px solid; padding:1px 6px; border-radius:4px; font-size:0.75rem; font-weight:600; text-transform:uppercase;}}
nav a {{margin:0 2px;}}
code {{background:#0B1220; padding:1px 4px; border-radius:3px; font-family:ui-monospace,Menlo,Consolas,monospace;}} .toc {{list-style:none; padding-left:0;}} .toc li {{margin:4px 0;}}
@media print {{
  body {{background:#fff; color:#111; margin:0; max-width:none;}}
  .card, .banner {{background:#fff; border:1px solid #ccc; break-inside:avoid;}}
  .muted, h3 {{color:#555;}} pre {{background:#f3f3f3;}} a {{color:#0b6;}}
  details > table {{display:table;}}
}}
</style></head><body>
<h1>{TOOL} report</h1>
<p class="muted">Packet-capture diagnosis · {_e(result.file_name)} · generated {_now()} ·
Tip: Print → Save as PDF to share.</p>
<nav class="muted">Contents: <a href="#summary">Summary</a> · <a href="#incidents">Incidents</a> ·
<a href="#issues">Issues</a> · <a href="#traffic">Traffic</a> · <a href="#devices">Devices</a> ·
<a href="#capture">Capture details</a> · <a href="#method">Method</a></nav>
<div class="banner" id="summary"><h2 style="color:{color}; margin:0">{_e(head)}</h2></div>
{summary}
<h3>Notes on this capture</h3><ul>{notes}</ul>
<h2 id="incidents">Incidents</h2>
<p class="muted">Related issues grouped into one story (shared devices and time, or the same attacker).</p>
{incidents or '<p class="muted">None.</p>'}
<h2 id="issues">Issues in detail</h2>
{''.join(cards) or '<p class="muted">No issues found.</p>'}
<h2 id="traffic">Traffic</h2>
<div class="grid"><div><h3>Protocols</h3><table class="plain"><tr><th>Protocol</th><th>Packets</th><th>Share</th></tr>{protos}</table></div>
<div><h3>Top talkers (bytes sent)</h3><table class="plain"><tr><th>Address</th><th>Bytes</th></tr>{talkers}</table></div></div>
<h3>Largest conversations</h3><table><tr><th>Endpoint A</th><th>Endpoint B</th><th>Proto</th><th>Packets</th><th>Bytes</th><th>Starts</th><th>Duration</th></tr>{convs}</table>
<h2 id="devices">Devices</h2><table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Role</th><th>Packets</th></tr>{devices}</table>
<h2 id="capture">Capture details</h2><section class="card"><table class="kv">{facts_html}</table>
<p class="muted">The SHA-256 fingerprint identifies exactly which file this report describes (check with
<code>sha256sum</code> or <code>Get-FileHash</code>).</p></section>
<h2 id="method">How the verdicts were reached</h2><section class="card">
<p><b>Attack, fault or uncertain.</b> Each check collects facts from the packets. A judge then weighs explicit signs
of an attack against signs of a harmless fault (both lists are shown on every issue). "Attack" needs strong evidence
that clearly beats the harmless explanation; mixed evidence is reported as "uncertain", and the advice then starts
with checks rather than drastic action. Confidence (low/medium/high) reflects how clear the margin is.</p>
<p><b>Severity</b> says how much damage the problem can do if real: <i>critical</i> (traffic can be read or redirected),
<i>high</i> (outage or exposure for several users), <i>medium</i> (degraded service), <i>low</i> (minor).</p>
<p><b>Limits.</b> A capture only shows traffic that passed where it was recorded; encrypted traffic hides some
details; findings are evidence-based indicators, not legal proof. All detection logic is CaughtIn4K's own; Scapy
was used only to read packets. The tool made no network connections while analysing.</p></section>
</body></html>"""


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
