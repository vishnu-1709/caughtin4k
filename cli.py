"""CaughtIn4K command line: python cli.py capture.pcap [--json] [--redact] [-o report.html]

Exit codes: 0 healthy, 1 faults (or uncertain issues), 2 attacks, 3 the file could not be analysed.
"""
from __future__ import annotations

import argparse
import sys

from engine.analyze import analyze_safe
from engine.loader import CaptureError
from engine.redact import redact_result
from engine.report import safe_output_path, to_csv, to_html, to_json

BOLD, RED, AMBER, GREEN, GREY, RESET = "\033[1m", "\033[31m", "\033[33m", "\033[32m", "\033[90m", "\033[0m"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="caughtin4k", description="Find faults and attacks in a packet capture.")
    p.add_argument("capture", help="a .pcap or .pcapng file")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    p.add_argument("--redact", action="store_true", help="mask IP and MAC addresses in all output")
    p.add_argument("-o", "--output", help="write an HTML report (path inside the current folder)")
    p.add_argument("--csv", help="write the evidence packets as CSV (path inside the current folder)")
    p.add_argument("--technical", action="store_true", help="technical wording")
    p.add_argument("--max-mb", type=float, default=None, help="file size limit in MB (default 50)")
    p.add_argument("--no-color", action="store_true")
    args = p.parse_args(argv)
    color = sys.stdout.isatty() and not args.no_color

    def c(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if color else text

    try:
        out_html = safe_output_path(args.output, (".html", ".htm")) if args.output else None
        out_csv = safe_output_path(args.csv, (".csv",)) if args.csv else None
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3
    options = {"config": {"max_file_mb": args.max_mb}} if args.max_mb else {}
    try:
        result = analyze_safe(args.capture, options)
    except CaptureError as exc:
        print(f"Error: {exc.message}", file=sys.stderr)
        return 3
    if args.redact:
        result = redact_result(result)

    if args.json:
        print(to_json(result))
    else:
        counts = result.counts()
        if counts["attack"]:
            head = c(RED + BOLD, f"UNDER ATTACK: {counts['attack']} attack(s), {counts['fault']} fault(s), "
                                 f"{counts['uncertain']} uncertain")
        elif counts["fault"] or counts["uncertain"]:
            head = c(AMBER + BOLD, f"NEEDS ATTENTION: {counts['fault']} fault(s), {counts['uncertain']} uncertain")
        else:
            head = c(GREEN + BOLD, "NETWORK LOOKS HEALTHY")
        print(f"{result.file_name}: {result.packets_read:,} packets, {result.duration:.0f} s")
        print(head)
        for w in result.warnings:
            print(c(AMBER, f"! {w}"))
        tone = {"attack": RED, "fault": AMBER, "uncertain": GREY}
        for f in result.findings:
            title = f.title_technical if args.technical else f.title_simple
            print()
            print(c(tone.get(f.verdict, GREY) + BOLD, f"[{f.verdict.upper()}/{f.confidence}] ") + title)
            print(f"  {f.explanation_technical if args.technical else f.explanation}")
            if f.linked_text:
                print(f"  -> {f.linked_text}")
            for i, step in enumerate(f.fix_steps, 1):
                print(f"  {i}. {step}")
            print(c(GREY, f"  Wireshark: {f.wireshark_filter}"))
            print(c(GREY, f"  Evidence frames: {', '.join(map(str, f.evidence_frames[:12]))}"
                          f"{' ...' if len(f.evidence_frames) > 12 else ''}"))
    if out_html:
        with open(out_html, "w", encoding="utf-8") as fh:
            fh.write(to_html(result))
        print(f"HTML report written to {out_html}", file=sys.stderr)
    if out_csv:
        with open(out_csv, "w", encoding="utf-8", newline="") as fh:
            fh.write(to_csv(result))
        print(f"Evidence CSV written to {out_csv}", file=sys.stderr)
    counts = result.counts()
    return 2 if counts["attack"] else 1 if (counts["fault"] or counts["uncertain"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:  # output piped into e.g. `head`
        sys.stderr.close()
        sys.exit(0)
