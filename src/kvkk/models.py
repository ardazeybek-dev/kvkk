"""Core data types shared by the detectors, the masker and the reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

__all__ = ["Confidence", "Finding", "Match", "ScanResult"]


class Confidence(str, Enum):
    """How sure we are that a match is really personal data.

    ``HIGH``
        The value passed a checksum (TCKN, IBAN, VKN, credit card). A random
        string of digits cannot reach this level by accident.
    ``MEDIUM``
        The shape is unmistakable and carries its own prefix or separator
        (e-mail address, ``+90`` phone number, licence plate).
    ``LOW``
        The shape matches but nothing corroborates it. Reported so that a human
        can look, never acted on by ``--fail-on high``.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass(frozen=True, slots=True)
class Match:
    """One piece of personal data found inside a single string.

    ``start`` and ``end`` are offsets into the string that was scanned, so
    ``text[match.start:match.end] == match.value`` always holds.
    """

    kind: str
    value: str
    start: int
    end: int
    confidence: Confidence

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(frozen=True, slots=True)
class Finding:
    """A :class:`Match` located in a file: the unit a report is built from."""

    path: str
    line: int
    column: int
    match: Match
    excerpt: str

    @property
    def kind(self) -> str:
        return self.match.kind

    @property
    def confidence(self) -> Confidence:
        return self.match.confidence


@dataclass
class ScanResult:
    """Everything one ``kvkk scan`` run produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0

    def __len__(self) -> int:
        return len(self.findings)

    def __bool__(self) -> bool:
        return bool(self.findings)

    def by_kind(self) -> dict[str, int]:
        """Count findings per entity kind, most frequent first."""
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.kind] = counts.get(finding.kind, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    def by_confidence(self) -> dict[Confidence, int]:
        counts: dict[Confidence, int] = {level: 0 for level in Confidence}
        for finding in self.findings:
            counts[finding.confidence] += 1
        return counts

    def by_file(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.path, []).append(finding)
        return grouped

    def worst(self) -> Confidence | None:
        """The highest confidence level present, or ``None`` when clean."""
        for level in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW):
            if any(f.confidence is level for f in self.findings):
                return level
        return None
