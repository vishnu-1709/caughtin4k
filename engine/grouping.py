"""Group findings into incidents and apply the two causal rules."""
from __future__ import annotations

from .context import Context
from .findings import Finding, Incident


def group(findings: list[Finding], ctx: Context) -> list[Incident]:
    return []
