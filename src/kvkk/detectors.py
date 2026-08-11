"""Detectors for Türkiye-specific personal data.

The design goal here is *not* to find as much as possible — it is to be quiet
enough that people actually leave the tool switched on. A scanner that cries
wolf on every eleven-digit number gets deleted from CI on day two.

Three rules keep the noise down:

1. **Checksums beat regular expressions.** TCKN, IBAN, VKN and card numbers all
   carry a check digit, so a random run of digits is rejected outright. Only
   values that survive the checksum are reported as :attr:`Confidence.HIGH`.
2. **Ambiguous shapes need context.** A bare ten-digit number is a valid tax ID
   once in every ten tries by pure chance, so ``vkn`` is only reported when a
   nearby word ("vkn", "vergi no", "tax") agrees with the reading.
3. **Everything else is graded, not dropped.** A phone number written ``+90 …``
   is stronger evidence than seven loose digits, and the report says so instead
   of pretending both are equally certain.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass

from trkit import is_valid_iban, is_valid_tckn

from .models import Confidence, Match

__all__ = [
    "DETECTORS",
    "available_kinds",
    "detect",
    "is_valid_credit_card",
    "is_valid_vkn",
    "label_for",
]

# A digit may not sit directly next to the match: it stops a 16-digit card
# number from also being reported as an 11-digit national ID.
_L = r"(?<![0-9])"
_R = r"(?![0-9])"

_SEP = r"[ .\-]?"

_CONTEXT_RADIUS = 48


# --------------------------------------------------------------------------- #
# checksum helpers
# --------------------------------------------------------------------------- #


def is_valid_vkn(value: str | int) -> bool:
    """Report whether a Turkish tax identification number is valid.

    A VKN is ten digits. For each of the first nine digits, ``(digit + 9 - i)``
    is reduced modulo 10, multiplied by ``2 ** (9 - i)``, reduced modulo 9 (with
    zero standing in for nine), and the sum of those terms determines the tenth
    digit.

    Note how weak this check is on its own: there is a single check digit, so
    roughly one in ten arbitrary ten-digit numbers passes. That is why the
    ``vkn`` detector also demands a supporting word nearby.

    >>> is_valid_vkn("4540536920")
    True
    >>> is_valid_vkn("4540536921")
    False
    >>> is_valid_vkn("1234567890")  # a checksum is not a meaning
    True
    """
    text = re.sub(r"\s+", "", str(value))
    if not re.fullmatch(r"[0-9]{10}", text):
        return False

    total = 0
    for index, char in enumerate(text[:9]):
        tmp = (int(char) + 9 - index) % 10
        if tmp == 0:
            continue
        product = (tmp * pow(2, 9 - index)) % 9
        total += 9 if product == 0 else product

    return (10 - total % 10) % 10 == int(text[9])


def is_valid_credit_card(value: str) -> bool:
    """Report whether a card number passes the Luhn check.

    >>> is_valid_credit_card("4111 1111 1111 1111")
    True
    >>> is_valid_credit_card("4111 1111 1111 1112")
    False
    """
    digits = [int(char) for char in str(value) if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _is_plausible_ipv4(value: str) -> bool:
    return all(part.isdigit() and int(part) <= 255 for part in value.split("."))


# --------------------------------------------------------------------------- #
# confidence graders
# --------------------------------------------------------------------------- #


def _phone_confidence(match: re.Match[str]) -> Confidence:
    """An explicit country code or leading zero is what makes a phone a phone."""
    text = match.group(0)
    if text.startswith("+90") or text.startswith("0090"):
        return Confidence.HIGH
    if text.startswith("0"):
        return Confidence.MEDIUM
    return Confidence.LOW


# --------------------------------------------------------------------------- #
# detector table
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class Detector:
    """One kind of personal data and everything needed to recognise it."""

    kind: str
    label: str
    pattern: re.Pattern[str]
    confidence: Confidence = Confidence.MEDIUM
    validator: Callable[[str], bool] | None = None
    grader: Callable[[re.Match[str]], Confidence] | None = None
    context: re.Pattern[str] | None = None

    def grade(self, match: re.Match[str]) -> Confidence:
        return self.grader(match) if self.grader else self.confidence


DETECTORS: dict[str, Detector] = {
    detector.kind: detector
    for detector in (
        Detector(
            kind="tckn",
            label="Turkish national ID (TCKN)",
            pattern=re.compile(rf"{_L}[1-9][0-9]{{10}}{_R}"),
            confidence=Confidence.HIGH,
            validator=is_valid_tckn,
        ),
        Detector(
            kind="iban",
            label="IBAN",
            pattern=re.compile(rf"\bTR[0-9]{{2}}(?:[ ]?[0-9]{{4}}){{5}}[ ]?[0-9]{{2}}{_R}", re.I),
            confidence=Confidence.HIGH,
            validator=is_valid_iban,
        ),
        Detector(
            kind="credit_card",
            label="Payment card number",
            pattern=re.compile(rf"{_L}[0-9]{{4}}(?:[ -]?[0-9]{{4}}){{2}}[ -]?[0-9]{{1,4}}{_R}"),
            confidence=Confidence.HIGH,
            validator=is_valid_credit_card,
        ),
        Detector(
            kind="vkn",
            label="Tax ID (VKN)",
            pattern=re.compile(rf"{_L}[0-9]{{10}}{_R}"),
            confidence=Confidence.HIGH,
            validator=is_valid_vkn,
            # One in ten random ten-digit numbers passes the checksum, so the
            # surrounding text has to agree that this is a tax ID at all.
            context=re.compile(r"vkn|vergi\s*(kimlik|no|numara)|tax\s*(id|no)", re.I),
        ),
        Detector(
            kind="phone",
            label="Phone number",
            pattern=re.compile(
                rf"{_L}(?:\+90{_SEP}|0090{_SEP}|0)?"
                rf"(?:5[0-9]{{2}}|2[1-9][0-9]|3[1-9][0-9]|4[1-9][0-9])"
                rf"{_SEP}[0-9]{{3}}{_SEP}[0-9]{{2}}{_SEP}[0-9]{{2}}{_R}"
            ),
            grader=_phone_confidence,
        ),
        Detector(
            kind="email",
            label="E-mail address",
            pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            confidence=Confidence.MEDIUM,
        ),
        Detector(
            kind="plate",
            label="Licence plate",
            pattern=re.compile(
                r"(?<![0-9A-Za-zÇĞİÖŞÜçğıöşü])"
                r"(?:0[1-9]|[1-7][0-9]|8[01])[ ]?[A-ZÇĞİÖŞÜ]{1,3}[ ]?[0-9]{2,5}"
                rf"{_R}"
            ),
            confidence=Confidence.MEDIUM,
        ),
        Detector(
            kind="ip",
            label="IP address",
            pattern=re.compile(rf"{_L}(?:[0-9]{{1,3}}\.){{3}}[0-9]{{1,3}}{_R}"),
            # An IP address is personal data under KVKK, but it is just as
            # likely to be a service address, so a human decides.
            confidence=Confidence.LOW,
            validator=_is_plausible_ipv4,
        ),
    )
}

_CONFIDENCE_RANK = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}


def available_kinds() -> list[str]:
    """Every detector name, in report order."""
    return list(DETECTORS)


def label_for(kind: str) -> str:
    """Human-readable name for a detector, falling back to the raw kind."""
    detector = DETECTORS.get(kind)
    return detector.label if detector else kind


def _has_context(text: str, match: re.Match[str], pattern: re.Pattern[str]) -> bool:
    start = max(0, match.start() - _CONTEXT_RADIUS)
    end = min(len(text), match.end() + _CONTEXT_RADIUS)
    return pattern.search(text[start:end]) is not None


def _resolve_overlaps(matches: list[Match]) -> list[Match]:
    """Keep the strongest reading when two detectors claim the same characters.

    An IBAN written without spaces also contains runs of digits that look like
    other things; reporting both would double-count the same leak. Sorting by
    confidence and then by length means the most specific detector wins.
    """
    ordered = sorted(
        matches,
        key=lambda m: (-_CONFIDENCE_RANK[m.confidence], -m.length, m.start),
    )

    kept: list[Match] = []
    for candidate in ordered:
        if any(candidate.start < k.end and k.start < candidate.end for k in kept):
            continue
        kept.append(candidate)

    return sorted(kept, key=lambda m: m.start)


def detect(
    text: str,
    kinds: Sequence[str] | None = None,
    min_confidence: Confidence = Confidence.LOW,
) -> list[Match]:
    """Find every piece of personal data in ``text``, ordered by position.

    ``kinds`` restricts the scan to the named detectors; ``min_confidence``
    drops weaker readings.

    >>> [m.kind for m in detect("TCKN: 10000000146")]
    ['tckn']
    >>> detect("sipariş no 12345678901")  # fails the checksum
    []
    """
    selected = _select(kinds)
    threshold = _CONFIDENCE_RANK[min_confidence]

    matches: list[Match] = []
    for detector in selected:
        for raw in detector.pattern.finditer(text):
            value = raw.group(0)

            if detector.validator and not detector.validator(value):
                continue
            if detector.context and not _has_context(text, raw, detector.context):
                continue

            confidence = detector.grade(raw)
            if _CONFIDENCE_RANK[confidence] < threshold:
                continue

            matches.append(
                Match(
                    kind=detector.kind,
                    value=value,
                    start=raw.start(),
                    end=raw.end(),
                    confidence=confidence,
                )
            )

    return _resolve_overlaps(matches)


def _select(kinds: Iterable[str] | None) -> list[Detector]:
    if kinds is None:
        return list(DETECTORS.values())

    selected: list[Detector] = []
    for kind in kinds:
        try:
            selected.append(DETECTORS[kind])
        except KeyError:
            known = ", ".join(DETECTORS)
            raise ValueError(f"unknown detector {kind!r}; available: {known}") from None
    return selected
