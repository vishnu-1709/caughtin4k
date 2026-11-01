"""CaughtIn4K - Streamlit UI. Answer first, details on demand.

Security notes:
- Uploads are written to a private temp file, analysed in a sandboxed subprocess, and deleted in `finally`.
- Only the analysis result (no packet bytes) is kept in session state.
- Every value that comes from a packet is HTML-escaped before it is rendered as HTML (see `esc`).
"""
from __future__ import annotations

import html
import json
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from engine import __version__
from engine.analyze import Result, analyze_safe
from engine.checks import CHECKS, check_status
from engine.config import DEFAULTS
from engine.findings import Finding
from engine.loader import CaptureError, clean_text, quick_preview
from engine.redact import redact_result
from engine.report import safe_filename, to_csv, to_html, to_json

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")
MAX_MB = DEFAULTS["max_file_mb"]
COLORS = {"attack": "#F04438", "fault": "#F79009", "healthy": "#12B76A", "uncertain": "#98A2B3"}
LABELS = {"attack": "ATTACK", "fault": "FAULT", "uncertain": "UNCERTAIN"}
SEV_COLORS = {"critical": "#F04438", "high": "#F79009", "medium": "#FDB022", "low": "#98A2B3"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
GROUP_ORDER = ["Multi-step", "Attacks", "Faults", "Harmless", "Bad files"]
MAX_PARALLEL = 2  # analyses running at once on this server (protects the free host from overload)
RATE_LIMIT = (8, 60)  # at most 8 analyses per browser session per 60 seconds

st.set_page_config(page_title="CaughtIn4K", page_icon="🔎", layout="wide")

st.markdown("""<style>
.block-container {max-width: 1120px; padding-top: 2rem;}
.ci-tag {color:#94A3B8; margin-top:0;}
.ci-privacy {color:#94A3B8; font-size:0.9rem;}
.ci-banner {border-radius:6px; padding:14px 18px; margin:6px 0 10px 0; border:1px solid #1F2A44;}
.ci-banner h3 {margin:0; padding:0; font-size:1.35rem;}
.ci-banner p {margin:4px 0 0 0; color:#E2E8F0;}
.ci-badge {display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.78rem; font-weight:700;
           letter-spacing:0.04em; color:#0B1220; margin-right:8px;}
.ci-meta {color:#94A3B8; font-size:0.85rem;}
.ci-title {font-size:1.12rem; font-weight:600; margin:6px 0 2px 0;}
.ci-mono, .ci-card code {font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:0.88em;}
.ci-card code {background:#0B1220; padding:1px 5px; border-radius:3px;}
.ci-card ol {margin:4px 0 0 0; padding-left:1.3rem;}
.ci-muted {color:#94A3B8;}
.ci-link {color:#2DD4BF; font-size:0.9rem;}
.ci-pill {display:inline-block; border:1px solid #1F2A44; background:#111A2E; border-radius:4px; padding:3px 9px;
          margin:3px 6px 3px 0; font-size:0.85rem;}
.ci-dot {display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px;}
.ci-checks {display:grid; grid-template-columns:1fr 1fr; gap:4px 28px;}
.ci-checks div {font-size:0.9rem; padding:2px 0;}
.ci-sev {display:inline-block; padding:1px 7px; border-radius:4px; font-size:0.76rem; font-weight:600;
         border:1px solid; margin-right:8px; text-transform:uppercase; letter-spacing:0.03em;}
.ci-brand {display:flex; justify-content:space-between; align-items:baseline; flex-wrap:wrap; gap:6px;}
.ci-brand h1 {margin:0 0 6px 0; padding:0; line-height:1.2;}
.ci-steps {margin:6px 0 0 0; padding-left:1.2rem;}
.ci-steps li {margin:3px 0;}
.ci-kv td {padding:3px 12px 3px 0; vertical-align:top;}
.ci-kv td:first-child {color:#94A3B8; white-space:nowrap;}
.ci-ok {color:#12B76A; margin-right:6px;}
.ci-tiles {display:grid; grid-template-columns:repeat(6,1fr); gap:8px; margin:8px 0 6px 0;}
.ci-tile {background:#111A2E; border:1px solid #1F2A44; border-top:3px solid #1F2A44; border-radius:6px; padding:7px 10px;}
.ci-tile b {display:block; font-size:1.35rem; line-height:1.2;} .ci-tile span {color:#94A3B8; font-size:0.78rem;}
.ci-first {border:1px solid #2DD4BF; border-radius:6px; padding:8px 14px; margin:4px 0 8px 0; background:#0F1B2D;}
.ci-first b.h {color:#2DD4BF; font-size:0.9rem;} .ci-first ol {margin:4px 0 0 0; padding-left:1.2rem;}
.ci-first li {margin:2px 0;} .ci-first .ci-muted {font-size:0.9rem;}
.ci-h {font-size:0.78rem; text-transform:uppercase; letter-spacing:0.05em; color:#94A3B8; margin:10px 0 3px 0; font-weight:600;}
.ci-h.bad {color:#F97066;} .ci-h.good {color:#32D583;}
.ci-why {border-left:1px dashed #1F2A44; padding-left:16px;}
@media (max-width: 760px) {.ci-tiles {grid-template-columns:repeat(3,1fr);} .ci-why {border:0; padding:0;}}
@media (max-width: 640px) {.ci-checks {grid-template-columns:1fr;}}
</style>""", unsafe_allow_html=True)

IP_OR_MAC = re.compile(r"((?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|(?:IP|MAC)-\d+)")


def esc(text: Any) -> str:
    """Escape for HTML, then style addresses and `commands` as monospace. Safe for packet data."""
    out = html.escape(str(text), quote=True)
    out = re.sub(r"`([^`]{1,200})`", r"<code>\1</code>", out)
    out = IP_OR_MAC.sub(r'<span class="ci-mono">\1</span>', out)
    return out.replace("\n", "<br>")


def html_block(markup: str) -> None:
    """Render one raw HTML block (single line, so markdown never re-parses packet text)."""
    st.markdown(markup.replace("\n", " "), unsafe_allow_html=True)


# --------------------------------------------------------------------------- data
def load_labels() -> dict:
    try:
        with open(os.path.join(SAMPLES, "labels.json")) as fh:
            labels = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in labels.items() if os.path.isfile(os.path.join(SAMPLES, k))}


@st.cache_resource
def _slots() -> threading.BoundedSemaphore:
    """Shared by all visitors of this server: limits how many analyses run at the same time."""
    return threading.BoundedSemaphore(MAX_PARALLEL)


def _check_rate() -> None:
    now = time.monotonic()
    runs = [t for t in st.session_state.get("runs", []) if now - t < RATE_LIMIT[1]]
    if len(runs) >= RATE_LIMIT[0]:
        raise CaptureError("rate")
    st.session_state["runs"] = runs + [now]


def analyse(path: str, display_name: str, preview: dict) -> Result:
    _check_rate()
    slots = _slots()
    if not slots.acquire(timeout=45):
        raise CaptureError("busy")
    try:
        return _analyse(path, display_name, preview)
    finally:
        slots.release()


def _analyse(path: str, display_name: str, preview: dict) -> Result:
    total = max(preview.get("packets", 1), 1)
    bar = st.progress(0.0, text="Reading packets…")

    def progress(n: int) -> None:
        bar.progress(min(n / total, 1.0), text=f"Reading packets… {n:,} / {total:,}")

    try:
        return analyze_safe(path, {"display_name": display_name}, progress)
    finally:
        bar.empty()


def run_upload(uploaded) -> tuple[Result, dict]:
    """Write the upload to a private temp file, analyse it, and always delete it."""
    fd, path = tempfile.mkstemp(prefix="ci4k-", suffix=".cap")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(uploaded.getbuffer())
        name = clean_text(os.path.basename(uploaded.name), 120)
        preview = quick_preview(path, MAX_MB)
        preview["name"] = name
        show_preview(preview)
        return analyse(path, name, preview), preview
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def run_sample(name: str) -> tuple[Result, dict]:
    path = os.path.join(SAMPLES, os.path.basename(name))
    preview = quick_preview(path, MAX_MB)
    preview["name"] = name
    show_preview(preview)
    return analyse(path, name, preview), preview


# --------------------------------------------------------------------------- pieces
def fmt_size(n: int) -> str:
    return f"{n / 1024 / 1024:.1f} MB" if n >= 1024 * 1024 else f"{n / 1024:.0f} KB"


def show_preview(p: dict) -> None:
    approx = "~" if p.get("packets_estimate") else ""
    html_block(f'<div class="ci-meta">📄 <b>{esc(p["name"])}</b> · {fmt_size(p["size"])} · '
               f'{approx}{p["packets"]:,} packets · {p["duration"]:.0f} s of traffic · {esc(p["format"])}</div>')


def rel(ts: float, r: Result) -> str:
    return f"{max(ts - r.start, 0):.1f}s"


def banner(r: Result) -> None:
    c = r.counts()
    first = r.findings[0] if r.findings else None
    if c["attack"]:
        color, head = COLORS["attack"], f"Under attack: {c['attack']} attack{'s' if c['attack'] > 1 else ''}"
        extra = [f"{c['fault']} fault{'s' if c['fault'] != 1 else ''}"] if c["fault"] else []
        if c["uncertain"]:
            extra.append(f"{c['uncertain']} uncertain")
        head += (", " + ", ".join(extra) if extra else "") + " found"
        start = "The steps below are in order of urgency."
    elif c["fault"] or c["uncertain"]:
        color = COLORS["fault"] if c["fault"] else COLORS["uncertain"]
        parts = [f"{c['fault']} fault{'s' if c['fault'] != 1 else ''}"] if c["fault"] else []
        if c["uncertain"]:
            parts.append(f"{c['uncertain']} unclear issue{'s' if c['uncertain'] > 1 else ''}")
        head = "Needs attention: " + ", ".join(parts) + " found, no attacks"
        start = "The steps below are in order of urgency."
    else:
        color, head = COLORS["healthy"], "Network looks healthy"
        start = f"No faults or attacks found in {r.packets_read:,} packets."
    if r.incidents and len(r.incidents) == 1 and len(r.findings) > 1:
        start += " All of them are one connected incident (see the Incidents tab)."
    html_block(f'<div class="ci-banner" style="border-left:6px solid {color}; background:#111A2E;">'
               f'<h3 style="color:{color}">{esc(head)}</h3><p>{esc(start)}</p></div>')


def evidence_table(f: Finding, r: Result) -> None:
    rows = []
    for n in f.evidence_frames:
        row = r.frames.get(n)
        if row:
            ts, src, dst, proto, info = row
            rows.append({"Frame": n, "Time": round(max(ts - r.start, 0), 3), "Source": src,
                         "Destination": dst, "Protocol": proto, "Info": info})
    if not rows:
        st.caption("No packet details stored for this finding.")
        return
    total = f.details.get("evidence_total", len(rows))
    if total > len(rows):
        st.caption(f"Showing {len(rows)} of {total} packets. Use the Wireshark filter below to see all.")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(38 + 35 * len(rows), 320),
                 column_config={"Time": st.column_config.NumberColumn("Time (s)", format="%.3f")})


def timeline(r: Result, findings: list[Finding], technical: bool) -> None:
    if not findings:
        return
    rows = []
    for f in findings:
        start = max(f.time_start - r.start, 0)
        end = max(f.time_end - r.start, start + max(r.duration / 150, 0.3))
        label = f.title_technical if technical else f.title_simple
        rows.append({"Issue": label[:70], "Start (s)": round(start, 2), "End (s)": round(end, 2),
                     "Verdict": f.verdict, "Confidence": f.confidence})
    df = pd.DataFrame(rows)
    chart = alt.Chart(df).mark_bar(cornerRadius=2).encode(
        x=alt.X("Start (s):Q", title="Seconds into the capture", scale=alt.Scale(domain=[0, max(r.duration, 1)])),
        x2="End (s):Q",
        y=alt.Y("Issue:N", title=None, sort=None, axis=alt.Axis(labelLimit=420),
                scale=alt.Scale(paddingInner=0.35)),
        color=alt.Color("Verdict:N", scale=alt.Scale(domain=list(LABELS), range=[COLORS[k] for k in LABELS]),
                        legend=alt.Legend(orient="bottom", title=None)),
        tooltip=["Issue", "Verdict", "Confidence", "Start (s)", "End (s)"],
    ).properties(height=alt.Step(34))
    st.altair_chart(chart, width="stretch")


def devices_table(r: Result) -> None:
    impostors, rogues, attack_hosts = set(), set(), set()
    for f in r.findings:
        if f.verdict == "attack":
            attack_hosts.update(f.hosts)
        if f.kind == "arp_spoofing":
            impostors.add(f.details.get("new_mac"))
        if f.kind == "rogue_dhcp" and f.verdict == "attack":
            rogues.add(f.details.get("rogue_mac"))
    rows = []
    for d in r.devices:
        role = d["role"]
        if d["mac"] in impostors:
            role = "IMPOSTOR (ARP spoofing)" + (f"; claims {role}" if role else "")
        elif d["mac"] in rogues:
            role = "ROGUE DHCP SERVER" + (f"; {role}" if role else "")
        rows.append({"IP": d["ip"], "MAC": d["mac"], "Vendor": d["vendor"], "Role": role or "-",
                     "Packets": d["packets"], "_hit": d["ip"] in attack_hosts and d["mac"] in attack_hosts
                     or d["mac"] in impostors or d["mac"] in rogues})
    if not rows:
        st.caption("No local devices could be identified in this capture.")
        return
    df = pd.DataFrame(rows)
    hit = df.pop("_hit")
    styled = df.style.apply(lambda row: ["background-color: rgba(240,68,56,0.18)" if hit[row.name] else ""] * len(row),
                            axis=1)
    st.dataframe(styled, hide_index=True, width="stretch")
    if hit.any():
        st.caption("Highlighted rows are involved in an attack.")


def capture_stats(r: Result) -> None:
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Protocols**")
        df = pd.DataFrame([{"Protocol": k, "Packets": v} for k, v in r.protocols.items()])
        if not df.empty:
            st.altair_chart(alt.Chart(df).mark_bar(color="#2DD4BF").encode(
                x=alt.X("Packets:Q"), y=alt.Y("Protocol:N", sort="-x", title=None),
                tooltip=["Protocol", "Packets"]).properties(height=alt.Step(26)), width="stretch")
    with c2:
        st.markdown("**Top talkers** (bytes sent)")
        df = pd.DataFrame([{"IP": ip, "Bytes": b} for ip, b in r.top_talkers])
        if not df.empty:
            st.dataframe(df, hide_index=True, width="stretch")


STATUS_STYLE = {"clear": ("#12B76A", "clear"), "no_data": ("#475467", "no data in this capture")}


def checks_overview() -> None:
    """Front page: what CaughtIn4K looks for, in one compact block."""
    def col(cat: str, title: str, color: str) -> str:
        items = "".join(f'<div><span class="ci-dot" style="background:{color}"></span><b>{esc(c.name)}</b>'
                        f' <span class="ci-muted">— {esc(c.blurb)}</span></div>' for c in CHECKS if c.category == cat)
        return f'<div><div class="ci-muted" style="margin-bottom:4px">{title}</div>{items}</div>'
    html_block('<div class="ci-muted" style="margin:10px 0 4px 0; font-weight:600">What CaughtIn4K checks</div>'
               '<div class="ci-checks">' + col("attack", "Attacks", COLORS["attack"])
               + col("fault", "Faults", COLORS["fault"]) + '</div>'
               '<div class="ci-meta" style="margin-top:6px">Every issue is judged <b>attack</b>, <b>fault</b> or '
               '<b>uncertain</b>, with the evidence for both sides, the likely cause and what to do.</div>')


def capture_guide(expanded: bool) -> None:
    with st.expander("How to record a capture (Wireshark, 3 steps)", expanded=expanded):
        st.markdown(
            "1. Install **Wireshark** (wireshark.org) and open it on a computer **on a network you own or "
            "may test**.\n"
            "2. Double-click your active interface (Wi-Fi or Ethernet), reproduce the problem for 1–5 minutes, "
            "then press the red **Stop** button.\n"
            "3. **File → Save As…** and choose *pcapng* or *pcap*. Upload that file here (max "
            f"{MAX_MB} MB).")


def sev_badge(level: str) -> str:
    c = SEV_COLORS.get(level, SEV_COLORS["low"])
    return f'<span class="ci-sev" style="color:{c}; border-color:{c}">{esc(level)}</span>'


def incidents_tab(r: Result) -> None:
    if not r.incidents:
        st.caption("No incidents: nothing was found in this capture.")
        return
    st.caption("Related issues (shared devices and time, or the same attacker) are grouped into incidents, "
               "so one root cause reads as one story.")
    by_id = {f.id: f for f in r.findings}
    for inc in r.incidents:
        members = [by_id[i] for i in inc.finding_ids if i in by_id]
        color = COLORS.get(inc.verdict, COLORS["uncertain"])
        steps = inc.steps or [f"{max(f.time_start - r.start, 0):.0f}s · {f.title_simple}" for f in members]
        with st.container(border=True):
            html_block(f'<div class="ci-card"><span class="ci-badge" style="background:{color}">'
                       f'{LABELS.get(inc.verdict, "?")}</span>{sev_badge(inc.severity)}'
                       f'<span class="ci-meta">{esc(inc.id)} · {len(members)} issue{"s" if len(members) != 1 else ""} · '
                       f'{rel(inc.time_start, r)} – {rel(inc.time_end, r)}</span>'
                       f'<div class="ci-title">{esc(inc.summary)}</div>'
                       + (f'<div class="ci-link">🔗 {esc(inc.caused_by)}</div>' if inc.caused_by else "")
                       + '<div class="ci-muted" style="margin-top:6px">What happened, in order</div>'
                       f'<ol class="ci-steps">{"".join(f"<li>{esc(x)}</li>" for x in steps)}</ol>'
                       + (f'<div class="ci-meta" style="margin-top:6px">Devices involved: '
                          f'{esc(", ".join(inc.hosts[:8]))}{" …" if len(inc.hosts) > 8 else ""}</div>')
                       + '</div>')


def traffic_tab(r: Result) -> None:
    if r.activity:
        rows = []
        for b in r.activity:
            for proto in ("TCP", "UDP", "ARP", "ICMP", "Other"):
                if b.get(proto):
                    rows.append({"Second": b["t"], "Protocol": proto, "Packets": b[proto]})
        df = pd.DataFrame(rows)
        width = r.activity[0]["width"]
        bars = alt.Chart(df).mark_bar(opacity=0.9).encode(
            x=alt.X("Second:Q", title="Seconds into the capture", bin=alt.Bin(step=width), scale=alt.Scale(nice=False)),
            y=alt.Y("sum(Packets):Q", title=f"Packets per {width} s"),
            color=alt.Color("Protocol:N", scale=alt.Scale(domain=["TCP", "UDP", "ARP", "ICMP", "Other"],
                                                          range=["#2DD4BF", "#60A5FA", "#A78BFA", "#F472B6", "#64748B"]),
                            legend=alt.Legend(orient="top", title=None)),
            tooltip=["Second", "Protocol", "Packets"])
        layers = [bars]
        if r.incidents:
            inc = pd.DataFrame([{"start": max(i.time_start - r.start, 0), "end": max(i.time_end - r.start, 0) + width,
                                 "Incident": f"{i.id}: {i.summary[:60]}", "Verdict": i.verdict} for i in r.incidents])
            layers.insert(0, alt.Chart(inc).mark_rect(opacity=0.12).encode(
                x="start:Q", x2="end:Q",
                color=alt.Color("Verdict:N", scale=alt.Scale(domain=list(LABELS), range=[COLORS[k] for k in LABELS]),
                                legend=None),
                tooltip=["Incident", "Verdict"]))
        st.markdown("**Activity over time**")
        st.altair_chart(alt.layer(*layers).resolve_scale(color="independent").properties(height=230), width="stretch")
        st.caption("Shaded bands mark when each incident was active. Busy traffic at the same time does not by "
                   "itself mean it caused the incident.")
    capture_stats(r)
    st.markdown("**Conversations** (largest first)")
    if r.conversations:
        df = pd.DataFrame([{"Endpoint A": c["a"], "Endpoint B": c["b"], "Protocol": c["proto"],
                            "Packets": c["packets"], "Bytes": c["bytes"], "First frame": c["first_frame"],
                            "Starts (s)": c["first"], "Duration (s)": c["duration"]} for c in r.conversations])
        st.dataframe(df, hide_index=True, width="stretch", height=min(38 + 35 * len(df), 360))


def evidence_tab(r: Result, technical: bool) -> None:
    by_frame: dict[int, list[str]] = {}
    for f in r.findings:
        for n in f.evidence_frames:
            by_frame.setdefault(n, []).append(f.title_technical if technical else f.title_simple)
    if not by_frame:
        st.caption("No evidence packets: nothing was found in this capture.")
        return
    titles = [f.title_technical if technical else f.title_simple for f in r.findings]
    pick = st.selectbox("Show evidence for", ["All issues"] + titles, key="ev_pick")
    rows = []
    for n in sorted(by_frame):
        if pick != "All issues" and pick not in by_frame[n]:
            continue
        row = r.frames.get(n)
        if row:
            ts, src, dst, proto, info = row
            rows.append({"Frame": n, "Time (s)": round(max(ts - r.start, 0), 3), "Source": src, "Destination": dst,
                         "Protocol": proto, "Info": info, "Supports": "; ".join(by_frame[n])[:160]})
    st.caption(f"{len(rows)} packets. Frame numbers match Wireshark, so you can jump to them there "
               "(Go → Go to Packet). Use the table's search icon to filter.")
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch", height=min(38 + 35 * len(rows), 480))


def security_tab(r: Result, preview: dict) -> None:
    c1, c2 = st.columns([1.15, 1])
    with c1:
        st.markdown("**File fingerprint**")
        lim = r.meta.get("limits", {})
        rows = [("File", r.file_name), ("Size", fmt_size(r.file_size)), ("Format", r.file_format),
                ("SHA-256", r.sha256 or "-"), ("Packets analysed", f"{r.packets_read:,} (skipped {r.packets_skipped:,})"),
                ("Link type", ", ".join(r.link_types) or "unknown"), ("Analysed at", r.meta.get("analysed_at", "-")),
                ("Tool", r.meta.get("tool", f"CaughtIn4K {__version__}")),
                ("Limits applied", f"{lim.get('max_file_mb', MAX_MB)} MB · {lim.get('max_packets', 0):,} packets · "
                                   f"{lim.get('max_seconds', 0)} s parsing · {lim.get('memory_limit_mb', 0)} MB memory")]
        html_block('<table class="ci-kv">' + "".join(
            f'<tr><td>{esc(k)}</td><td class="{"ci-mono" if k == "SHA-256" else ""}" '
            f'style="{"word-break:break-all" if k == "SHA-256" else ""}">'
            f'{esc(v)}</td></tr>' for k, v in rows) + "</table>")
        st.caption("The SHA-256 fingerprint identifies exactly which file this report is about "
                   "(compare it with `sha256sum file.pcap`).")
    with c2:
        st.markdown("**How your file was protected**")
        items = [
            "Checked before reading: size limit and file type (magic bytes), so fake or zipped files are refused",
            "Read packet by packet in a separate, sandboxed process with time, memory and CPU limits",
            "Damaged or hostile packets are skipped, never allowed to crash the tool",
            "Uploaded file deleted immediately after analysis; nothing is stored or logged",
            "No internet connections, no telemetry, nothing sent to the analysed network",
            "All text from packets is escaped before display, so code hidden in packets can't run",
            "Passwords found in clear text are never shown; usernames are masked",
            "Hide IPs masks every address, including in downloads",
            f"At most {MAX_PARALLEL} analyses run at once and each visitor is rate-limited, to keep the service up",
        ]
        html_block("<div>" + "".join(f'<div style="margin:3px 0"><span class="ci-ok">✓</span>{esc(i)}</div>'
                                     for i in items) + "</div>")


def sample_picker(labels: dict) -> str:
    groups = [g for g in GROUP_ORDER if any(v.get("group") == g for v in labels.values())]
    group = st.segmented_control("Or try a sample", groups, default=None, key="sample_group",
                                 help="17 synthetic captures, grouped by what they contain")
    if not group:
        st.caption("Pick a group to see its sample captures.")
        return ""
    names = [n for n, v in labels.items() if v.get("group") == group]
    return st.selectbox("Sample", [""] + names, key=f"sample_{group}", label_visibility="collapsed",
                        format_func=lambda n: "Choose a sample…" if not n else f"{n} — {labels[n]['description']}")


MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|:<>$~])")
VERDICT_MD = {"attack": ("🔴", "red"), "fault": ("🟠", "orange"), "uncertain": ("⚪", "gray")}
SEV_MD = {"critical": "red", "high": "orange", "medium": "orange", "low": "gray"}


def md_escape(text: Any) -> str:
    """Escape Markdown so packet text in widget labels is shown literally."""
    return MD_SPECIAL.sub(r"\\\1", str(text))


def overview(r: Result) -> None:
    """Count tiles and the three most important actions, right under the verdict."""
    c = r.counts()

    def tile(label: str, value: Any, tone: str = "") -> str:
        return f'<div class="ci-tile" style="border-top-color:{tone or "#1F2A44"}"><b>{esc(value)}</b><span>{esc(label)}</span></div>'

    html_block('<div class="ci-tiles">'
               + tile("attacks", c["attack"], COLORS["attack"] if c["attack"] else "")
               + tile("faults", c["fault"], COLORS["fault"] if c["fault"] else "")
               + tile("uncertain", c["uncertain"], COLORS["uncertain"] if c["uncertain"] else "")
               + tile("incidents", len(r.incidents))
               + tile("packets", f"{r.packets_read:,}")
               + tile("seconds of traffic", f"{r.duration:.0f}") + "</div>")
    top = [f for f in r.findings if f.fix_steps][:3]
    if top:
        html_block('<div class="ci-first"><b class="h">Do this first</b><ol>'
                   + "".join(f'<li><b>{esc(f.title_simple)}</b><br><span class="ci-muted">{esc(f.fix_steps[0])}</span></li>'
                             for f in top) + "</ol></div>")


def checks_and_coverage(r: Result) -> None:
    """One folded line: what was checked, plus what this capture can't show."""
    rows = check_status(r)
    found = sum(1 for x in rows if x["status"] == "found")
    clear = sum(1 for x in rows if x["status"] == "clear")
    nodata = sum(1 for x in rows if x["status"] == "no_data")
    label = (f"What we checked: {found} found · {clear} clear"
             + (f" · {nodata} no data" if nodata else "") + " — and what this capture can't show")
    with st.expander(label, expanded=False, icon="🧾"):
        pills = []
        for row in rows:
            if row["status"] == "found":
                color, text = COLORS.get(row["verdict"], COLORS["uncertain"]), f"{row['count']} found"
            else:
                color, text = STATUS_STYLE[row["status"]]
            pills.append(f'<span class="ci-pill" title="{esc(row["blurb"])}"><span class="ci-dot" '
                         f'style="background:{color}"></span>{esc(row["name"])} '
                         f'<span class="ci-muted">· {esc(text)}</span></span>')
        html_block("<div>" + "".join(pills) + "</div>")
        items = r.coverage + [f"Skipped: {x}" for x in r.skipped_checks]
        html_block('<div class="ci-h">What this capture can and can\'t show</div><ul>'
                   + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>")


def download_menu(view: Result, hide: bool) -> None:
    with st.popover("⬇ Download", width="stretch", help="HTML report, JSON or evidence CSV"):
        st.download_button("HTML report (printable)", to_html(view), file_name=safe_filename(view.file_name, ".html"),
                           mime="text/html", width="stretch")
        st.download_button("JSON (everything)", to_json(view), file_name=safe_filename(view.file_name, ".json"),
                           mime="application/json", width="stretch")
        st.download_button("Evidence CSV", to_csv(view), file_name=safe_filename(view.file_name, "-evidence.csv"),
                           mime="text/csv", width="stretch")
        st.caption("Reports hold the analysis and packet summaries, never the capture."
                   + (" Addresses are masked (Hide IPs is on)." if hide else ""))


def issue(f: Finding, r: Result, technical: bool, opened: bool) -> None:
    """One line per issue (verdict, severity, title, time); opens into two columns."""
    icon, vcolor = VERDICT_MD.get(f.verdict, ("⚪", "gray"))
    title = f.title_technical if technical else f.title_simple
    label = (f"{icon} :{vcolor}[**{f.verdict.upper()}**] · :{SEV_MD.get(f.severity, 'gray')}[{f.severity.upper()}]"
             f" — {md_escape(title)} · {rel(f.time_start, r)}")
    with st.expander(label, expanded=opened, key=f"iss_{f.id}"):
        explanation = (f.explanation_technical or f.explanation) if technical else f.explanation
        left, right = st.columns([1.15, 1], gap="medium")
        with left:
            html_block('<div class="ci-card">'
                       f'<div class="ci-meta">{esc(f.confidence)} confidence · {rel(f.time_start, r)} – '
                       f'{rel(f.time_end, r)} · {len(f.evidence_frames)} packets of evidence</div>'
                       f'<div class="ci-h">What happened</div><div>{esc(explanation)}</div>'
                       + (f'<div class="ci-link" style="margin-top:6px">🔗 {esc(f.linked_text)}</div>' if f.linked_text else "")
                       + f'<div class="ci-h">What to do</div><ol>{"".join(f"<li>{esc(x)}</li>" for x in f.fix_steps)}</ol>'
                       f'<div class="ci-h">Likely cause</div><div>{esc(f.likely_cause)}</div></div>')
        with right:
            def items(xs: list[str]) -> str:
                return "<ul>" + "".join(f"<li>{esc(t)}</li>" for t in xs) + "</ul>" if xs else "<div class='ci-muted'>None found.</div>"
            html_block('<div class="ci-card ci-why">'
                       f'<div class="ci-h bad">Signs of an attack</div>{items(f.indicators_for)}'
                       f'<div class="ci-h good">Signs of a harmless fault</div>{items(f.indicators_against)}'
                       + (f'<div class="ci-meta">Score: attack {f.details.get("score_attack", 0)} vs harmless '
                          f'{f.details.get("score_harmless", 0)}</div>' if "score_attack" in f.details else "")
                       + f'<div class="ci-h">Could it be harmless?</div><div>{esc(f.benign_alternative)}</div></div>')
        st.code(f.wireshark_filter or "-", language=None)
        if st.toggle(f"Show the {len(f.evidence_frames)} evidence packets", key=f"ev_{f.id}"):
            evidence_table(f, r)


# --------------------------------------------------------------------------- page
html_block('<div class="ci-brand"><h1>CaughtIn4K</h1>'
           f'<span class="ci-meta">Offline packet-capture diagnosis · {len(CHECKS)} checks · v{esc(__version__)}</span></div>')
html_block('<div class="ci-tag">Upload a packet capture. Get the faults and attacks in it, explained in plain '
           'language, with the evidence and how to fix them.</div>')
html_block('<div class="ci-privacy">🔒 Your file is analysed and deleted immediately. Nothing is stored. '
           'No data leaves this server, and the tool never connects to the network it analyses.</div>')
st.write("")

labels = load_labels()
left, right = st.columns([1.1, 1])
with left:
    uploaded = st.file_uploader(f"Upload a capture (.pcap, .pcapng, .cap — up to {MAX_MB} MB)",
                                type=["pcap", "pcapng", "cap"])
with right:
    sample = sample_picker(labels)

if uploaded is not None:
    key = ("upload", getattr(uploaded, "file_id", None) or f"{uploaded.name}:{uploaded.size}")
elif sample:
    key = ("sample", sample)
else:
    key = None

if key is None:
    st.session_state.pop("result", None)
    st.session_state.pop("key", None)
    st.info("No file yet. Upload a capture, or pick a sample group on the right to see how CaughtIn4K works.")
    capture_guide(expanded=True)
    checks_overview()
    st.stop()

if st.session_state.get("key") != key:
    st.session_state.pop("result", None)
    st.session_state["key"] = key
    try:
        if key[0] == "upload":
            res, prev = run_upload(uploaded)
        else:
            res, prev = run_sample(sample)
        st.session_state["result"], st.session_state["preview"] = res, prev
    except CaptureError as exc:
        st.session_state["error"] = exc.message
    except Exception:  # never show a stack trace or packet data
        st.session_state["error"] = CaptureError("internal").message
    else:
        st.session_state.pop("error", None)
    st.rerun()

if st.session_state.get("error"):
    st.error(st.session_state["error"], icon="🚫")
    st.caption("Tip: pick a sample group on the right to see a working example.")
    st.stop()

result: Result | None = st.session_state.get("result")
if result is None:
    st.stop()
show_preview(st.session_state["preview"])

# answer first: banner, metrics and coverage use the current control values (widgets are drawn below)
hide = bool(st.session_state.get("hide_ips", False))
technical = st.session_state.get("wording") == "Technical"
view = result
if hide:
    if st.session_state.get("redacted_for") != key:
        st.session_state["redacted"] = redact_result(result)
        st.session_state["redacted_for"] = key
    view = st.session_state["redacted"]

banner(view)
overview(view)
for w in view.warnings:
    st.warning(w, icon="⚠️")
checks_and_coverage(view)

c1, c2, c3, c4 = st.columns([2.3, 0.9, 1.25, 0.9], vertical_alignment="bottom")
counts = result.counts()
options = {"all": f"All ({len(result.findings)})", "attack": f"Attacks ({counts['attack']})",
           "fault": f"Faults ({counts['fault']})", "uncertain": f"Uncertain ({counts['uncertain']})"}
with c1:
    flt = st.segmented_control("Show", list(options), format_func=options.get, default="all", key="flt") or "all"
with c2:
    st.toggle("Hide IPs", key="hide_ips", help="Masks IP and MAC addresses everywhere, including downloads.")
with c3:
    st.segmented_control("Wording", ["Simple", "Technical"], default="Simple", key="wording")
with c4:
    download_menu(view, hide)

shown = [f for f in view.findings if flt == "all" or f.verdict == flt]
evidence_count = len({n for f in view.findings for n in f.evidence_frames})
tabs = st.tabs([f"Issues ({len(shown)})", f"Incidents ({len(view.incidents)})", "Traffic",
                f"Devices ({len(view.devices)})", f"Evidence ({evidence_count})", "Security & privacy"])
with tabs[0]:
    if not view.findings:
        st.success("No faults or attacks found. Open “What we checked” above to see everything that was examined.")
    elif not shown:
        st.caption("Nothing in this category.")
    else:
        st.caption("Most serious first. Click a line to see what happened, what to do and why we think so.")
    for i, f in enumerate(shown):
        issue(f, view, technical, opened=False)
    if shown:
        st.markdown("**Timeline**")
        timeline(view, shown, technical)
with tabs[1]:
    incidents_tab(view)
with tabs[2]:
    traffic_tab(view)
with tabs[3]:
    devices_table(view)
with tabs[4]:
    evidence_tab(view, technical)
with tabs[5]:
    security_tab(view, st.session_state["preview"])
html_block(f'<div class="ci-meta" style="margin-top:2rem">CaughtIn4K {esc(__version__)} · own detection logic, Scapy '
           f'used only to read packets · analysed {esc(view.file_name)} at '
           f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')
