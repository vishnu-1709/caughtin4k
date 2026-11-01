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
from datetime import datetime, timezone
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from engine.analyze import Result, analyze_safe
from engine.config import DEFAULTS
from engine.findings import Finding
from engine.loader import CaptureError, clean_text, quick_preview
from engine.redact import redact_result

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")
MAX_MB = DEFAULTS["max_file_mb"]
COLORS = {"attack": "#F04438", "fault": "#F79009", "healthy": "#12B76A", "uncertain": "#98A2B3"}
LABELS = {"attack": "ATTACK", "fault": "FAULT", "uncertain": "UNCERTAIN"}

st.set_page_config(page_title="CaughtIn4K", page_icon="🔎", layout="wide")

st.markdown("""<style>
.block-container {max-width: 1120px; padding-top: 2rem;}
.ci-tag {color:#94A3B8; margin-top:-0.6rem;}
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
@st.cache_data(show_spinner=False)
def load_labels() -> dict:
    try:
        with open(os.path.join(SAMPLES, "labels.json")) as fh:
            labels = json.load(fh)
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in labels.items() if os.path.isfile(os.path.join(SAMPLES, k))}


def analyse(path: str, display_name: str, preview: dict) -> Result:
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
        start = f"Start with: {first.title_simple}." if first else ""
    elif c["fault"] or c["uncertain"]:
        color = COLORS["fault"] if c["fault"] else COLORS["uncertain"]
        parts = [f"{c['fault']} fault{'s' if c['fault'] != 1 else ''}"] if c["fault"] else []
        if c["uncertain"]:
            parts.append(f"{c['uncertain']} unclear issue{'s' if c['uncertain'] > 1 else ''}")
        head = "Needs attention: " + ", ".join(parts) + " found, no attacks"
        start = f"Start with: {first.title_simple}." if first else ""
    else:
        color, head = COLORS["healthy"], "Network looks healthy"
        start = f"No faults or attacks found in {r.packets_read:,} packets. Check the coverage note for what this capture can show."
    if r.incidents and len(r.incidents) < len(r.findings):
        start += (f" These {len(r.findings)} issues come from {len(r.incidents)} separate "
                  f"incident{'s' if len(r.incidents) > 1 else ''} (see the 🔗 links on the cards).")
    html_block(f'<div class="ci-banner" style="border-left:6px solid {color}; background:#111A2E;">'
               f'<h3 style="color:{color}">{esc(head)}</h3><p>{esc(start)}</p></div>')


def metrics(r: Result) -> None:
    cols = st.columns(4)
    cols[0].metric("Packets read", f"{r.packets_read:,}")
    cols[1].metric("Skipped packets", f"{r.packets_skipped:,}")
    cols[2].metric("Devices", f"{len({d['mac'] if d['mac'] != '-' else d['ip'] for d in r.devices}):,}")
    cols[3].metric("Duration", f"{r.duration:.0f} s")


def coverage(r: Result) -> None:
    for w in r.warnings:
        st.warning(w, icon="⚠️")
    with st.expander("What this capture can and can't show", expanded=not r.findings):
        items = r.coverage + [f"Skipped: {s}" for s in r.skipped_checks]
        html_block("<ul>" + "".join(f"<li>{esc(i)}</li>" for i in items) + "</ul>")
        html_block(f'<div class="ci-meta">Analysed in {r.elapsed:.1f} s · link type: '
                   f'{esc(", ".join(r.link_types) or "unknown")} · format: {esc(r.file_format)}</div>')


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


def card(f: Finding, r: Result, technical: bool) -> None:
    color = COLORS.get(f.verdict, COLORS["uncertain"])
    title = f.title_technical if technical else f.title_simple
    explanation = (f.explanation_technical or f.explanation) if technical else f.explanation
    steps = "".join(f"<li>{esc(s)}</li>" for s in f.fix_steps)
    with st.container(border=True):
        html_block(
            f'<div class="ci-card">'
            f'<span class="ci-badge" style="background:{color}">{LABELS.get(f.verdict, "?")}</span>'
            f'<span class="ci-meta">{esc(f.confidence)} confidence · {rel(f.time_start, r)} – {rel(f.time_end, r)}'
            f' · {len(f.evidence_frames)} packets of evidence</span>'
            f'<div class="ci-title">{esc(title)}</div>'
            f'<div>{esc(explanation)}</div>'
            f'<div style="margin-top:10px"><b>What to do</b><ol>{steps}</ol></div>'
            + (f'<div class="ci-link" style="margin-top:6px">🔗 {esc(f.linked_text)}</div>' if f.linked_text else "")
            + '</div>')
        with st.expander("Why we think so"):
            html_block(f'<div class="ci-card"><div class="ci-muted">Likely cause</div><div>{esc(f.likely_cause)}</div>'
                       '<div class="ci-muted" style="margin-top:8px">Signs of an attack</div>'
                       + ("<ul>" + "".join(f"<li>{esc(t)}</li>" for t in f.indicators_for) + "</ul>"
                          if f.indicators_for else "<div>None found.</div>")
                       + '<div class="ci-muted" style="margin-top:8px">Signs of a harmless fault</div>'
                       + ("<ul>" + "".join(f"<li>{esc(t)}</li>" for t in f.indicators_against) + "</ul>"
                          if f.indicators_against else "<div>None found.</div>")
                       + (f'<div class="ci-meta">Score: attack {f.details.get("score_attack", 0)} vs harmless '
                          f'{f.details.get("score_harmless", 0)}</div>' if "score_attack" in f.details else "")
                       + '</div>')
        with st.expander("Could it be harmless?"):
            html_block(f'<div class="ci-card">{esc(f.benign_alternative)}</div>')
        with st.expander("Evidence"):
            evidence_table(f, r)
        st.caption("Check it yourself in Wireshark (display filter):")
        st.code(f.wireshark_filter or "-", language=None)


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


def capture_guide(expanded: bool) -> None:
    with st.expander("How to record a capture (Wireshark, 3 steps)", expanded=expanded):
        st.markdown(
            "1. Install **Wireshark** (wireshark.org) and open it on a computer **on a network you own or "
            "may test**.\n"
            "2. Double-click your active interface (Wi-Fi or Ethernet), reproduce the problem for 1–5 minutes, "
            "then press the red **Stop** button.\n"
            "3. **File → Save As…** and choose *pcapng* or *pcap*. Upload that file here (max "
            f"{MAX_MB} MB).")


# --------------------------------------------------------------------------- page
html_block('<h1 style="margin-bottom:0">CaughtIn4K</h1>')
html_block('<div class="ci-tag">Upload a packet capture. Get the faults and attacks in it, explained in plain '
           'language, with the evidence and how to fix them.</div>')
html_block('<div class="ci-privacy">🔒 Your file is analysed and deleted immediately. Nothing is stored. '
           'No data leaves this server, and the tool never connects to the network it analyses.</div>')
st.write("")

labels = load_labels()
sample_names = list(labels)
left, right = st.columns([1.1, 1])
with left:
    uploaded = st.file_uploader(f"Upload a capture (.pcap, .pcapng, .cap — up to {MAX_MB} MB)",
                                type=["pcap", "pcapng", "cap"])
with right:
    sample = st.selectbox("Or try a sample", [""] + sample_names, index=0,
                          format_func=lambda n: "Choose a sample…" if not n else f"{n} — {labels[n]['description']}")
    if sample:
        st.caption(labels[sample]["description"])

if uploaded is not None:
    key = ("upload", getattr(uploaded, "file_id", None) or f"{uploaded.name}:{uploaded.size}")
elif sample:
    key = ("sample", sample)
else:
    key = None

if key is None:
    st.session_state.pop("result", None)
    capture_guide(expanded=True)
    st.info("No file yet. Upload a capture, or pick a sample on the right to see how CaughtIn4K works.")
    st.stop()

capture_guide(expanded=False)
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
    st.caption("Tip: pick a sample on the right to see a working example.")
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
metrics(view)
coverage(view)

c1, c2, c3 = st.columns([2.2, 1, 1.2])
counts = result.counts()
options = {"all": f"All ({len(result.findings)})", "attack": f"Attacks ({counts['attack']})",
           "fault": f"Faults ({counts['fault']})", "uncertain": f"Uncertain ({counts['uncertain']})"}
with c1:
    flt = st.segmented_control("Show", list(options), format_func=options.get, default="all", key="flt") or "all"
with c2:
    st.toggle("Hide IPs", key="hide_ips", help="Masks IP and MAC addresses everywhere, including downloads.")
with c3:
    st.segmented_control("Wording", ["Simple", "Technical"], default="Simple", key="wording")

shown = [f for f in view.findings if flt == "all" or f.verdict == flt]
if view.findings:
    st.subheader("Issues")
    if not shown:
        st.caption("Nothing in this category.")
    for f in shown:
        card(f, view, technical)
    st.subheader("Timeline")
    timeline(view, shown, technical)

st.subheader("Devices")
devices_table(view)
st.subheader("Capture stats")
capture_stats(view)
html_block(f'<div class="ci-meta" style="margin-top:2rem">CaughtIn4K · own detection logic, Scapy used only to read '
           f'packets · analysed {esc(view.file_name)} at '
           f'{datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>')
