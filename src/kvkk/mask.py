"""Four ways to remove personal data from text, for four different jobs.

Masking is not one operation. Sharing a log with a vendor, keeping a dataset
analysable, and filling a staging database are different problems, and KVKK
draws a hard line through the middle of them: *anonymisation* destroys the link
to a person for good, while *pseudonymisation* only hides it and is still
regulated personal data.

============  ==============================  ===============================
strategy      what comes out                  what it is for
============  ==============================  ===============================
``partial``   ``100******46``                 support tickets — a human can
                                              still confirm "yes, that's my
                                              number" without reading it
``redact``    ``[TCKN]``                      public logs and bug reports; the
                                              value is gone entirely
``hash``      ``tckn_8f2a1c``                 analytics — the same person gets
                                              the same token everywhere, so
                                              joins and counts still work
``fake``      ``29874500146``                 staging databases — output is a
                                              *valid* value of the right type,
                                              so downstream validation passes
============  ==============================  ===============================

``hash`` and ``fake`` are deterministic and salted. The same input plus the
same salt always yields the same output, which keeps foreign keys intact across
files and across runs; change the salt and the mapping is gone.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from collections.abc import Sequence
from enum import Enum

from .detectors import detect
from .models import Confidence, Match

__all__ = ["Strategy", "generate_salt", "mask_text", "mask_value"]


class Strategy(str, Enum):
    """How a detected value should be rewritten."""

    PARTIAL = "partial"
    REDACT = "redact"
    HASH = "hash"
    FAKE = "fake"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


def generate_salt() -> str:
    """A fresh random salt, for when the caller has not supplied one."""
    return secrets.token_hex(16)


def _digest(kind: str, value: str, salt: str) -> bytes:
    """Keyed digest of a value, normalised so formatting does not matter.

    ``TR33 0006 …`` and ``TR330006…`` are the same account, so they have to
    produce the same token.
    """
    normalised = re.sub(r"[\s.\-]", "", value).upper()
    message = f"{kind}:{normalised}".encode()
    return hmac.new(salt.encode(), message, hashlib.sha256).digest()


def _digits_from(digest: bytes, count: int) -> str:
    """Turn a digest into ``count`` decimal digits."""
    number = int.from_bytes(digest, "big")
    return str(number % 10**count).zfill(count)


# --------------------------------------------------------------------------- #
# partial
# --------------------------------------------------------------------------- #


def _partial(kind: str, value: str) -> str:
    """Keep just enough for a human to recognise their own data."""
    if kind == "email":
        local, _, domain = value.partition("@")
        head = local[0] if local else ""
        return f"{head}{'*' * max(len(local) - 1, 3)}@{domain}"

    if kind == "ip":
        parts = value.split(".")
        return ".".join(parts[:2] + ["*", "*"])

    visible_head, visible_tail = (3, 2) if len(value) > 8 else (1, 1)
    head = value[:visible_head]
    tail = value[-visible_tail:]
    return f"{head}{'*' * max(len(value) - visible_head - visible_tail, 1)}{tail}"


# --------------------------------------------------------------------------- #
# fake — output must be a *valid* value, not just a plausible one
# --------------------------------------------------------------------------- #


def _fake_tckn(digest: bytes) -> str:
    """Build an eleven-digit number that passes the real TCKN checksum."""
    body = _digits_from(digest, 9)
    if body[0] == "0":
        body = "9" + body[1:]

    digits = [int(char) for char in body]
    odd = digits[0] + digits[2] + digits[4] + digits[6] + digits[8]
    even = digits[1] + digits[3] + digits[5] + digits[7]
    tenth = (odd * 7 - even) % 10
    eleventh = (sum(digits) + tenth) % 10
    return f"{body}{tenth}{eleventh}"


def _fake_iban(digest: bytes) -> str:
    """Build a TR IBAN whose mod-97 check digits are correct."""
    body = _digits_from(digest, 22)
    # Check digits satisfy: int(body + "2927" + "00") % 97 == 1, where 2927 is
    # "TR" expanded as A=10 … Z=35.
    remainder = int(body + "292700") % 97
    check = (98 - remainder) % 97
    return f"TR{check:02d}{body}"


def _fake_card(digest: bytes) -> str:
    """Build a sixteen-digit number that passes Luhn, on a test-card prefix."""
    body = "4000" + _digits_from(digest, 11)

    total = 0
    # The check digit will sit at index 15, so parity is measured against it.
    for index, char in enumerate(body):
        digit = int(char)
        if index % 2 == 0:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return body + str((10 - total % 10) % 10)


def _fake_vkn(digest: bytes) -> str:
    body = _digits_from(digest, 9)
    total = 0
    for index, char in enumerate(body):
        tmp = (int(char) + 9 - index) % 10
        if tmp == 0:
            continue
        product = (tmp * pow(2, 9 - index)) % 9
        total += 9 if product == 0 else product
    return f"{body}{(10 - total % 10) % 10}"


_PLATE_LETTERS = "ABCDEFGHJKLMNPRSTUVYZ"


def _fake(kind: str, value: str, digest: bytes) -> str:
    if kind == "tckn":
        return _fake_tckn(digest)
    if kind == "iban":
        return _fake_iban(digest)
    if kind == "credit_card":
        return _fake_card(digest)
    if kind == "vkn":
        return _fake_vkn(digest)
    if kind == "phone":
        return f"05{_digits_from(digest, 9)}"
    if kind == "email":
        return f"user{_digits_from(digest, 6)}@example.com"
    if kind == "plate":
        province = int(_digits_from(digest, 2)) % 81 + 1
        letters = "".join(_PLATE_LETTERS[byte % len(_PLATE_LETTERS)] for byte in digest[:2])
        return f"{province:02d} {letters} {_digits_from(digest, 3)}"
    if kind == "ip":
        # 198.51.100.0/24 is reserved for documentation (RFC 5737).
        return f"198.51.100.{int(_digits_from(digest, 3)) % 254 + 1}"
    return _digits_from(digest, len(value))


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #


def mask_value(match: Match, strategy: Strategy = Strategy.PARTIAL, salt: str = "") -> str:
    """Rewrite a single detected value according to ``strategy``.

    >>> from kvkk.models import Confidence, Match
    >>> m = Match("tckn", "10000000146", 0, 11, Confidence.HIGH)
    >>> mask_value(m)
    '100******46'
    >>> mask_value(m, Strategy.REDACT)
    '[TCKN]'
    """
    if strategy is Strategy.REDACT:
        return f"[{match.kind.upper()}]"

    if strategy is Strategy.PARTIAL:
        return _partial(match.kind, match.value)

    digest = _digest(match.kind, match.value, salt)

    if strategy is Strategy.HASH:
        return f"{match.kind}_{digest.hex()[:8]}"

    return _fake(match.kind, match.value, digest)


def mask_text(
    text: str,
    strategy: Strategy = Strategy.PARTIAL,
    kinds: Sequence[str] | None = None,
    min_confidence: Confidence = Confidence.LOW,
    salt: str = "",
) -> tuple[str, list[Match]]:
    """Mask every detected value in ``text``.

    Returns the rewritten text and the matches that were replaced, so a caller
    can report what it changed.

    >>> masked, found = mask_text("Müşteri TCKN: 10000000146")
    >>> masked
    'Müşteri TCKN: 100******46'
    >>> len(found)
    1
    """
    matches = detect(text, kinds=kinds, min_confidence=min_confidence)
    if not matches:
        return text, []

    pieces: list[str] = []
    cursor = 0
    for match in matches:
        pieces.append(text[cursor : match.start])
        pieces.append(mask_value(match, strategy, salt))
        cursor = match.end
    pieces.append(text[cursor:])

    return "".join(pieces), matches
