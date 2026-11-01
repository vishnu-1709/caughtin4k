"""Shared output format: every diagnosis is a Finding; related findings form an Incident."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

VERDICTS = ("attack", "fault", "uncertain")
CONFIDENCES = ("low", "medium", "high")
MAX_EVIDENCE_FRAMES = 200


@dataclass
class Finding:
    """One diagnosed problem, with plain-language text, fix steps and evidence."""

    id: str
    kind: str
    category: str  # what the detector looks for: "attack" | "fault"
    verdict: str = "uncertain"  # set by the judge
    confidence: str = "low"
    title_simple: str = ""
    title_technical: str = ""
    explanation: str = ""
    explanation_technical: str = ""
    indicators_for: list[str] = field(default_factory=list)
    indicators_against: list[str] = field(default_factory=list)
    benign_alternative: str = ""
    likely_cause: str = ""
    fix_steps: list[str] = field(default_factory=list)
    evidence_frames: list[int] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    time_start: float = 0.0
    time_end: float = 0.0
    wireshark_filter: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    incident_id: str = ""
    linked_text: str = ""

    def add_evidence(self, frames: list[int]) -> None:
        """Add frame numbers, keeping them unique, sorted and capped."""
        merged = sorted(set(self.evidence_frames) | set(frames))
        self.details["evidence_total"] = max(len(merged), self.details.get("evidence_total", 0))
        self.evidence_frames = merged[:MAX_EVIDENCE_FRAMES]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Incident:
    """A group of findings that overlap in time and share hosts."""

    id: str
    finding_ids: list[str]
    verdict: str
    summary: str
    caused_by: str = ""  # human-readable causal link, if a causal rule fired
    hosts: list[str] = field(default_factory=list)
    time_start: float = 0.0
    time_end: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
