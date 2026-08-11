"""Detector tests.

Half of these are false-positive tests. A scanner is only useful if people
leave it switched on, and they switch it off when it shouts at order numbers.
"""

from __future__ import annotations

import pytest

from kvkk import Confidence, detect, is_valid_credit_card, is_valid_vkn
from kvkk.detectors import DETECTORS, available_kinds, label_for

VALID_TCKN = "10000000146"
VALID_IBAN = "TR33 0006 1005 1978 6457 8413 26"
VALID_CARD = "4111 1111 1111 1111"


def kinds_in(text: str, **kwargs) -> list[str]:
    return [match.kind for match in detect(text, **kwargs)]


# --------------------------------------------------------------------------- #
# true positives
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        (f"TCKN: {VALID_TCKN}", "tckn"),
        (f"hesap {VALID_IBAN}", "iban"),
        ("hesap TR330006100519786457841326", "iban"),
        (f"kart {VALID_CARD}", "credit_card"),
        ("kart 4111111111111111", "credit_card"),
        ("tel +90 532 123 45 67", "phone"),
        ("tel 0532 123 45 67", "phone"),
        ("mail ali@ornek.com.tr", "email"),
        ("plaka 34 ABC 123", "plate"),
        ("istek 192.168.1.24 adresinden", "ip"),
    ],
)
def test_detects(text: str, kind: str) -> None:
    assert kind in kinds_in(text)


def test_iban_is_case_insensitive() -> None:
    assert kinds_in("tr330006100519786457841326") == ["iban"]


def test_reports_position_exactly() -> None:
    text = f"musteri {VALID_TCKN} kayitli"
    match = detect(text)[0]
    assert text[match.start : match.end] == match.value


def test_finds_several_in_one_line() -> None:
    text = f"{VALID_TCKN} / {VALID_IBAN} / ali@ornek.com"
    assert kinds_in(text) == ["tckn", "iban", "email"]


def test_results_are_ordered_by_position() -> None:
    text = f"ali@ornek.com sonra {VALID_TCKN}"
    matches = detect(text)
    assert [m.start for m in matches] == sorted(m.start for m in matches)


# --------------------------------------------------------------------------- #
# false positives — the part that decides whether anyone keeps using this
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "text",
    [
        "siparis no 12345678901",  # 11 digits, checksum fails
        "hash 98765432109876543210",  # long digit run
        "sayac 00000000000",  # leading zero is not a TCKN
        "surum 1.2.3",
        "timestamp 1735689600",
    ],
)
def test_does_not_invent_a_tckn(text: str) -> None:
    assert "tckn" not in kinds_in(text)


def test_bad_iban_checksum_is_rejected() -> None:
    assert "iban" not in kinds_in("TR33 0006 1005 1978 6457 8413 27")


def test_bad_card_checksum_is_rejected() -> None:
    assert "credit_card" not in kinds_in("kart 4111 1111 1111 1112")


def test_vkn_needs_supporting_context() -> None:
    # This number passes the VKN checksum but nothing says it is a tax ID.
    assert is_valid_vkn("1234567890")
    assert "vkn" not in kinds_in("referans 1234567890")
    assert "vkn" in kinds_in("VKN: 1234567890")
    assert "vkn" in kinds_in("Vergi No 1234567890")


def test_a_longer_number_is_not_chopped_into_a_tckn() -> None:
    assert "tckn" not in kinds_in(f"x{VALID_TCKN}9")


def test_unspaced_iban_is_reported_once() -> None:
    matches = detect("TR330006100519786457841326")
    assert len(matches) == 1
    assert matches[0].kind == "iban"


def test_card_and_tckn_do_not_overlap() -> None:
    matches = detect(f"{VALID_CARD} ve {VALID_TCKN}")
    assert sorted(m.kind for m in matches) == ["credit_card", "tckn"]


# --------------------------------------------------------------------------- #
# confidence
# --------------------------------------------------------------------------- #


def test_checksummed_values_are_high_confidence() -> None:
    assert detect(f"TCKN {VALID_TCKN}")[0].confidence is Confidence.HIGH


def test_country_code_raises_phone_confidence() -> None:
    with_code = detect("+90 532 123 45 67")[0]
    bare = detect("ara 532 123 45 67")[0]
    assert with_code.confidence is Confidence.HIGH
    assert bare.confidence is Confidence.LOW


def test_ip_is_low_confidence_because_it_may_be_a_server() -> None:
    assert detect("10.0.0.1")[0].confidence is Confidence.LOW


def test_min_confidence_filters() -> None:
    text = f"{VALID_TCKN} ve 10.0.0.1"
    assert kinds_in(text) == ["tckn", "ip"]
    assert kinds_in(text, min_confidence=Confidence.HIGH) == ["tckn"]


def test_impossible_ipv4_octet_is_rejected() -> None:
    assert "ip" not in kinds_in("999.999.999.999")


# --------------------------------------------------------------------------- #
# selection & metadata
# --------------------------------------------------------------------------- #


def test_kinds_can_be_restricted() -> None:
    text = f"{VALID_TCKN} ali@ornek.com"
    assert kinds_in(text, kinds=["email"]) == ["email"]


def test_unknown_kind_is_rejected_with_a_useful_message() -> None:
    with pytest.raises(ValueError, match="unknown detector"):
        detect("x", kinds=["nope"])


def test_every_detector_has_a_label() -> None:
    for kind in available_kinds():
        assert label_for(kind) != kind
    assert set(available_kinds()) == set(DETECTORS)


def test_label_falls_back_for_unknown_kind() -> None:
    assert label_for("nope") == "nope"


def test_empty_input_is_fine() -> None:
    assert detect("") == []


# --------------------------------------------------------------------------- #
# checksum helpers
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(("value", "expected"), [("4540536920", True), ("4540536921", False)])
def test_vkn_checksum(value: str, expected: bool) -> None:
    assert is_valid_vkn(value) is expected


@pytest.mark.parametrize("value", ["", "abc", "123", "45405369200"])
def test_vkn_rejects_wrong_shapes(value: str) -> None:
    assert is_valid_vkn(value) is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("4111111111111111", True),
        ("4111 1111 1111 1111", True),
        ("4111111111111112", False),
        ("378282246310005", True),  # 15 digits
        ("411111", False),  # too short
    ],
)
def test_luhn(value: str, expected: bool) -> None:
    assert is_valid_credit_card(value) is expected
