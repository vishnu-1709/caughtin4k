"""CaughtIn4K - Streamlit UI (minimal version; full UI comes in Phase F)."""
from __future__ import annotations

import json
import os
import tempfile

import streamlit as st

from engine.analyze import Result, analyze_safe
from engine.loader import CaptureError, clean_text

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")

st.set_page_config(page_title="CaughtIn4K", page_icon="🔎", layout="wide")


def load_labels() -> dict:
    try:
        with open(os.path.join(SAMPLES, "labels.json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def run_upload(uploaded) -> Result:
    """Write the upload to a private temp file, analyse it, and always delete it."""
    fd, path = tempfile.mkstemp(prefix="ci4k-", suffix=".cap")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(uploaded.getbuffer())
        return analyze_safe(path, {"display_name": clean_text(os.path.basename(uploaded.name), 120)})
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


st.title("CaughtIn4K")
st.caption("Find faults and attacks in a packet capture, explained in plain language.")
st.info("Your file is analysed and deleted immediately. Nothing is stored.")

labels = load_labels()
col1, col2 = st.columns(2)
uploaded = col1.file_uploader("Upload a capture", type=["pcap", "pcapng", "cap"])
sample = col2.selectbox("Or try a sample", ["—"] + list(labels),
                        format_func=lambda n: n if n == "—" else f"{n} — {labels[n]['description']}")

result = None
try:
    if uploaded is not None:
        result = run_upload(uploaded)
    elif sample != "—":
        result = analyze_safe(os.path.join(SAMPLES, os.path.basename(sample)))
except CaptureError as exc:
    st.error(exc.message)

if result:
    counts = result.counts()
    st.subheader(f"{counts['attack']} attacks, {counts['fault']} faults, {counts['uncertain']} uncertain")
    st.write(f"Packets read: {result.packets_read} · skipped: {result.packets_skipped} · "
             f"duration: {result.duration:.0f}s")
    for w in result.warnings:
        st.warning(w)
    if not result.findings:
        st.success("Network looks healthy")
    for f in result.findings:
        with st.container(border=True):
            st.markdown(f"**{f.verdict.upper()}** ({f.confidence} confidence)")
            st.text(f.title_simple)
            st.text(f.explanation)
            st.text("What to do:\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(f.fix_steps, 1)))
            st.text("Attack signs:\n" + "\n".join(f"+ {t}" for t in f.indicators_for))
            st.text("Harmless signs:\n" + "\n".join(f"- {t}" for t in f.indicators_against))
            st.code(f.wireshark_filter or "", language=None)
