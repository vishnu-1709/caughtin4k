"""Plain-language text, fixes and benign alternatives (template based, offline)."""
from __future__ import annotations

from .context import Context
from .findings import Finding


def explain_all(findings: list[Finding], ctx: Context) -> None:
    for f in findings:
        f.title_simple = f.title_simple or f.kind
