"""Fault vs attack scoring (filled in per detector kind)."""
from __future__ import annotations

from .context import Context
from .findings import Finding


def judge_all(findings: list[Finding], ctx: Context) -> None:
    """Set verdict, confidence and indicators on every finding."""
    for f in findings:
        f.verdict = f.category
