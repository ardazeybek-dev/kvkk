"""Masking tests.

The property that matters most: ``fake`` output must pass the *real* validator
for its type, otherwise a masked staging database fails its own input checks.
"""

from __future__ import annotations

import pytest
from trkit import is_valid_iban, is_valid_tckn

from kvkk import Confidence, Match, Strategy, generate_salt, is_valid_vkn, mask_text, mask_value
from kvkk.detectors import is_valid_credit_card

VALID_TCKN = "10000000146"
VALID_IBAN = "TR33 0006 1005 1978 6457 8413 26"
SALT = "test-salt"


def tckn_match(value: str = VALID_TCKN) -> Match:
    return Match("tckn", value, 0, len(value), Confidence.HIGH)


# --------------------------------------------------------------------------- #
# partial
# --------------------------------------------------------------------------- #


def test_partial_keeps_the_ends() -> None:
    assert mask_value(tckn_match()) == "100******46"


def test_partial_hides_the_middle_entirely() -> None:
    masked = mask_value(tckn_match())
    assert VALID_TCKN[3:-2] not in masked


def test_partial_email_keeps_the_domain() -> None:
    match = Match("email", "ahmet@ornek.com", 0, 15, Confidence.MEDIUM)
    assert mask_value(match) == "a****@ornek.com"


def test_partial_email_hides_short_local_parts() -> None:
    match = Match("email", "a@ornek.com", 0, 11, Confidence.MEDIUM)
    assert mask_value(match) == "a***@ornek.com"


def test_partial_ip_keeps_the_network() -> None:
    match = Match("ip", "192.168.1.24", 0, 12, Confidence.LOW)
    assert mask_value(match) == "192.168.*.*"


def test_partial_needs_no_salt() -> None:
    assert mask_value(tckn_match(), Strategy.PARTIAL) == mask_value(tckn_match(), Strategy.PARTIAL)


# --------------------------------------------------------------------------- #
# redact
# --------------------------------------------------------------------------- #


def test_redact_removes_the_value() -> None:
    assert mask_value(tckn_match(), Strategy.REDACT) == "[TCKN]"


def test_redact_leaves_nothing_of_the_original() -> None:
    masked, _ = mask_text(f"musteri {VALID_TCKN}", Strategy.REDACT)
    assert VALID_TCKN not in masked
    assert any(char.isdigit() for char in masked) is False


# --------------------------------------------------------------------------- #
# hash — pseudonymisation
# --------------------------------------------------------------------------- #


def test_hash_is_deterministic() -> None:
    first = mask_value(tckn_match(), Strategy.HASH, SALT)
    second = mask_value(tckn_match(), Strategy.HASH, SALT)
    assert first == second


def test_hash_changes_with_the_salt() -> None:
    first = mask_value(tckn_match(), Strategy.HASH, "a")
    second = mask_value(tckn_match(), Strategy.HASH, "b")
    assert first != second


def test_hash_ignores_formatting() -> None:
    spaced = Match("iban", VALID_IBAN, 0, len(VALID_IBAN), Confidence.HIGH)
    compact = Match("iban", VALID_IBAN.replace(" ", ""), 0, 26, Confidence.HIGH)
    assert mask_value(spaced, Strategy.HASH, SALT) == mask_value(compact, Strategy.HASH, SALT)


def test_hash_separates_different_people() -> None:
    other = tckn_match("10000000243")
    assert mask_value(tckn_match(), Strategy.HASH, SALT) != mask_value(other, Strategy.HASH, SALT)


def test_hash_is_labelled_with_its_kind() -> None:
    assert mask_value(tckn_match(), Strategy.HASH, SALT).startswith("tckn_")


# --------------------------------------------------------------------------- #
# fake — output must be genuinely valid
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("seed", range(50))
def test_fake_tckn_passes_the_real_validator(seed: int) -> None:
    match = tckn_match(f"1000000014{seed % 10}")
    assert is_valid_tckn(mask_value(match, Strategy.FAKE, f"salt-{seed}"))


@pytest.mark.parametrize("seed", range(50))
def test_fake_iban_passes_the_real_validator(seed: int) -> None:
    match = Match("iban", VALID_IBAN, 0, len(VALID_IBAN), Confidence.HIGH)
    assert is_valid_iban(mask_value(match, Strategy.FAKE, f"salt-{seed}"))


@pytest.mark.parametrize("seed", range(50))
def test_fake_card_passes_luhn(seed: int) -> None:
    match = Match("credit_card", "4111111111111111", 0, 16, Confidence.HIGH)
    assert is_valid_credit_card(mask_value(match, Strategy.FAKE, f"salt-{seed}"))


@pytest.mark.parametrize("seed", range(50))
def test_fake_vkn_passes_the_real_validator(seed: int) -> None:
    match = Match("vkn", "4540536920", 0, 10, Confidence.HIGH)
    assert is_valid_vkn(mask_value(match, Strategy.FAKE, f"salt-{seed}"))


def test_fake_never_returns_the_original() -> None:
    assert mask_value(tckn_match(), Strategy.FAKE, SALT) != VALID_TCKN


def test_fake_is_deterministic() -> None:
    first = mask_value(tckn_match(), Strategy.FAKE, SALT)
    second = mask_value(tckn_match(), Strategy.FAKE, SALT)
    assert first == second


def test_fake_ip_stays_in_the_documentation_range() -> None:
    match = Match("ip", "8.8.8.8", 0, 7, Confidence.LOW)
    assert mask_value(match, Strategy.FAKE, SALT).startswith("198.51.100.")


def test_fake_email_uses_the_reserved_domain() -> None:
    match = Match("email", "ali@ornek.com", 0, 13, Confidence.MEDIUM)
    assert mask_value(match, Strategy.FAKE, SALT).endswith("@example.com")


# --------------------------------------------------------------------------- #
# mask_text
# --------------------------------------------------------------------------- #


def test_mask_text_preserves_surrounding_characters() -> None:
    masked, _ = mask_text(f"[2026-08-11] musteri={VALID_TCKN} durum=ok")
    assert masked == "[2026-08-11] musteri=100******46 durum=ok"


def test_mask_text_returns_what_it_replaced() -> None:
    _, matches = mask_text(f"{VALID_TCKN} ali@ornek.com")
    assert sorted(m.kind for m in matches) == ["email", "tckn"]


def test_mask_text_leaves_clean_text_untouched() -> None:
    text = "burada kisisel veri yok"
    masked, matches = mask_text(text)
    assert masked == text
    assert matches == []


def test_mask_text_handles_adjacent_values() -> None:
    masked, matches = mask_text(f"{VALID_TCKN},{VALID_TCKN}")
    assert len(matches) == 2
    assert masked == "100******46,100******46"


def test_mask_text_respects_kind_selection() -> None:
    masked, _ = mask_text(f"{VALID_TCKN} ali@ornek.com", kinds=["email"])
    assert VALID_TCKN in masked
    assert "ali@ornek.com" not in masked


def test_mask_text_respects_min_confidence() -> None:
    masked, _ = mask_text(f"{VALID_TCKN} 10.0.0.1", min_confidence=Confidence.HIGH)
    assert "10.0.0.1" in masked
    assert VALID_TCKN not in masked


def test_generated_salts_differ() -> None:
    assert generate_salt() != generate_salt()
