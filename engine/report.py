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

from .analyze import Result
from .checks import check_status

TOOL = "CaughtIn4K"
COLORS = {"attack": "#F04438", "fault": "#F79009", "uncertain": "#98A2B3", "healthy": "#12B76A"}


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
        story = (f"This capture shows {_n(len(result.findings), 'problem')} in "
                 f"{_n(len(result.incidents), 'separate incident')}. ")
        if attacks:
            story += f"The most important is an attack: {attacks[0].title_simple}. "
        for inc in result.incidents:
            if inc.caused_by:
                story += f"Linked: {inc.caused_by}. "
    else:
        story = (f"No faults or attacks were found in {result.packets_read:,} packets. "
                 "The checklist below shows what was examined.")
    first_steps = [f"{f.title_simple}: {f.fix_steps[0]}" for f in (attacks + others)[:3] if f.fix_steps]
    toc = "".join(f'<li><a href="#{_e(f.id)}"><span class="badge" style="background:{COLORS.get(f.verdict)}">'
                  f'{_e(f.verdict.upper())}</span> {_e(f.title_simple)}</a></li>' for f in result.findings)
    status_txt = {"clear": "Clear", "no_data": "No data in this capture"}
    checks = "".join(
        f"<tr><td>{_e(c['name'])}</td><td>{_e(c['category'])}</td><td style='color:"
        f"{COLORS.get(c['verdict'], COLORS['healthy']) if c['status'] != 'no_data' else '#94A3B8'}'>"
        f"{_e(str(c['count']) + ' found' if c['status'] == 'found' else status_txt[c['status']])}</td></tr>"
        for c in check_status(result))
    summary = (f'<section class="card"><h2>Summary</h2><p>{_e(story)}</p>'
               + (f'<h3>Do this first</h3>{_list(first_steps, ordered=True)}' if first_steps else '')
               + (f'<h3>Issues in this report</h3><ul class="toc">{toc}</ul>' if toc else '')
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
  <div><span class="badge" style="background:{fc}">{_e(f.verdict.upper())}</span>
  <span class="muted">{_e(f.confidence)} confidence · {max(f.time_start - result.start, 0):.1f}s – {max(f.time_end - result.start, 0):.1f}s · {_e(f.kind)}</span></div>
  <h2>{_e(f.title_simple)}</h2>
  <p class="muted mono">{_e(f.title_technical)}</p>
  <p>{_code(f.explanation)}</p>
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
code {{background:#0B1220; padding:1px 4px; border-radius:3px; font-family:ui-monospace,Menlo,Consolas,monospace;}} .toc {{list-style:none; padding-left:0;}} .toc li {{margin:4px 0;}}
@media print {{
  body {{background:#fff; color:#111; margin:0; max-width:none;}}
  .card, .banner {{background:#fff; border:1px solid #ccc; break-inside:avoid;}}
  .muted, h3 {{color:#555;}} pre {{background:#f3f3f3;}} a {{color:#0b6;}}
  details > table {{display:table;}}
}}
</style></head><body>
<h1>{TOOL} report</h1>
<p class="muted">Tip: use your browser's Print → Save as PDF to share this report.</p>
<p class="muted">File: <span class="mono">{_e(result.file_name)}</span> · {result.packets_read:,} packets ·
{result.duration:.0f} s of traffic · generated {_now()}</p>
<div class="banner"><h2 style="color:{color}; margin:0">{_e(head)}</h2></div>
{summary}
<h3>Notes on this capture</h3><ul>{notes}</ul>
{''.join(cards)}
<h2>Devices</h2><table><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Role</th><th>Packets</th></tr>{devices}</table>
<p class="muted">Detection logic: CaughtIn4K's own rules. Scapy was used only to read packets.</p>
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
