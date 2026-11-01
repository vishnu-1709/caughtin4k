"""Run the engine on every labelled sample and compare with the expected findings.

Usage: python evaluate.py [--markdown]

Prints per-sample expected vs detected, missed findings, false positives and verdict correctness.
These are synthetic captures: they prove the rules work as designed, not real-world accuracy.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter

from engine.analyze import analyze
from engine.loader import CaptureError

ROOT = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(ROOT, "samples")


def evaluate() -> tuple[list[dict], dict]:
    with open(os.path.join(SAMPLES, "labels.json")) as fh:
        labels = json.load(fh)
    rows, totals = [], Counter()
    for name, label in labels.items():
        expected = Counter((e["kind"], e["verdict"]) for e in label["expected"])
        row = {"sample": name, "expected": label["expected"], "detected": [], "missed": [], "extra": [],
               "verdict_ok": True, "note": ""}
        try:
            result = analyze(os.path.join(SAMPLES, name))
        except CaptureError as exc:
            ok = label.get("expect_error") == exc.code
            row["note"] = f"rejected ({exc.code})" + ("" if ok else " UNEXPECTED")
            row["verdict_ok"] = ok
            totals["handled_inputs"] += int(ok)
            rows.append(row)
            continue
        if label.get("expect_partial"):
            ok = result.partial
            row["note"] = "partial result + warning" if ok else "expected a partial-result warning"
            totals["handled_inputs"] += int(ok)
        got = Counter((f.kind, f.verdict) for f in result.findings)
        got_kinds = Counter(f.kind for f in result.findings)
        exp_kinds = Counter(k for k, _ in expected.elements())
        row["detected"] = [{"kind": f.kind, "verdict": f.verdict, "confidence": f.confidence} for f in result.findings]
        row["missed"] = list((exp_kinds - got_kinds).elements())
        row["extra"] = list((got_kinds - exp_kinds).elements())
        right_kind = sum((exp_kinds & got_kinds).values())
        right_verdict = sum((expected & got).values())
        row["verdict_ok"] = right_verdict == right_kind and not row["missed"]
        totals["expected"] += sum(expected.values())
        totals["detected_ok"] += right_kind
        totals["verdict_ok"] += right_verdict
        totals["false_positives"] += len(row["extra"])
        totals["attack_fp_on_clean"] += sum(1 for f in result.findings if f.verdict == "attack") if name == "clean.pcap" else 0
        rows.append(row)
    return rows, dict(totals)


def fmt(items: list) -> str:
    if not items:
        return "—"
    return ", ".join(f"{i['kind']} ({i['verdict']})" if isinstance(i, dict) else str(i) for i in items)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--markdown", action="store_true", help="print a Markdown table (for the README)")
    args = ap.parse_args()
    rows, t = evaluate()
    if args.markdown:
        print("| Sample | Expected | Detected (verdict) | Missed | False positives | Verdicts right |")
        print("|---|---|---|---|---|---|")
        for r in rows:
            det = fmt(r["detected"]) if r["detected"] else (r["note"] or "—")
            if r["detected"] and r["note"]:
                det += f" · {r['note']}"
            print(f"| `{r['sample']}` | {fmt(r['expected'])} | {det} | {fmt(r['missed'])} | {fmt(r['extra'])} | "
                  f"{'✅' if r['verdict_ok'] and not r['extra'] else '❌'} |")
    else:
        for r in rows:
            mark = "OK " if r["verdict_ok"] and not r["extra"] else "BAD"
            print(f"[{mark}] {r['sample']}")
            print(f"      expected: {fmt(r['expected'])}")
            print(f"      detected: {fmt(r['detected'])} {r['note']}")
            if r["missed"] or r["extra"]:
                print(f"      missed: {fmt(r['missed'])}   false positives: {fmt(r['extra'])}")
    print()
    print(f"Detected {t.get('detected_ok', 0)}/{t.get('expected', 0)} expected findings, "
          f"{t.get('verdict_ok', 0)}/{t.get('expected', 0)} with the right attack/fault verdict, "
          f"{t.get('false_positives', 0)} false positives, "
          f"{t.get('attack_fp_on_clean', 0)} attack alerts on clean.pcap, "
          f"{t.get('handled_inputs', 0)} damaged/wrong inputs handled safely.")
    bad = t.get("detected_ok", 0) != t.get("expected", 0) or t.get("false_positives", 0) or t.get("attack_fp_on_clean", 0)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
