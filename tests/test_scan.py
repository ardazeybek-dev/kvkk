"""Scanner tests: locations, exclusions, and the rule that reports never leak."""

from __future__ import annotations

from pathlib import Path

import pytest

from kvkk import Confidence, scan_file, scan_path, scan_text
from kvkk.scan import DEFAULT_EXCLUDES, iter_files

VALID_TCKN = "10000000146"


def write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# scan_text
# --------------------------------------------------------------------------- #


def test_reports_line_and_column() -> None:
    finding = scan_text(f"birinci satir\nikinci {VALID_TCKN}\n")[0]
    assert finding.line == 2
    assert finding.column == 8


def test_column_is_one_based() -> None:
    finding = scan_text(VALID_TCKN)[0]
    assert finding.column == 1


def test_excerpt_never_contains_the_raw_value() -> None:
    finding = scan_text(f"musteri kaydi {VALID_TCKN} guncellendi")[0]
    assert VALID_TCKN not in finding.excerpt
    assert "100******46" in finding.excerpt


def test_excerpt_masks_the_other_values_on_the_same_line() -> None:
    """A CSV row holds several identifiers; reporting one must not expose the rest."""
    row = f"1;Ahmet Yilmaz;{VALID_TCKN};0532 123 45 67;ahmet@ornek.com"
    findings = scan_text(row)

    assert len(findings) > 1
    for finding in findings:
        assert VALID_TCKN not in finding.excerpt
        assert "0532 123 45 67" not in finding.excerpt
        assert "ahmet@ornek.com" not in finding.excerpt


def test_min_confidence_filter_does_not_expose_the_values_it_drops() -> None:
    """Narrowing the report must never widen what the report prints."""
    row = f"1;Ahmet Yilmaz;{VALID_TCKN};0532 123 45 67;ahmet@ornek.com"
    findings = scan_text(row, min_confidence=Confidence.HIGH)

    assert [f.kind for f in findings] == ["tckn"]
    assert "0532 123 45 67" not in findings[0].excerpt
    assert "ahmet@ornek.com" not in findings[0].excerpt


def test_kind_filter_does_not_expose_the_values_it_drops() -> None:
    row = f"{VALID_TCKN};ahmet@ornek.com"
    findings = scan_text(row, kinds=["email"])

    assert [f.kind for f in findings] == ["email"]
    assert VALID_TCKN not in findings[0].excerpt


def test_filtered_scan_still_centres_on_the_reported_match(tmp_path: Path) -> None:
    target = write(tmp_path / "a.csv", f"telefon 0532 123 45 67 tckn {VALID_TCKN}")
    finding = scan_file(target, min_confidence=Confidence.HIGH)[0]

    assert finding.kind == "tckn"
    assert "100******46" in finding.excerpt


def test_each_finding_still_shows_its_own_match() -> None:
    row = f"{VALID_TCKN};ahmet@ornek.com"
    by_kind = {f.kind: f.excerpt for f in scan_text(row)}

    assert "100******46" in by_kind["tckn"]
    assert "a****@ornek.com" in by_kind["email"]


def test_long_lines_are_trimmed_around_the_match() -> None:
    padding = "x" * 300
    finding = scan_text(f"{padding} {VALID_TCKN} {padding}")[0]
    assert finding.excerpt.startswith("…")
    assert finding.excerpt.endswith("…")
    assert len(finding.excerpt) < 150


def test_finding_exposes_kind_and_confidence() -> None:
    finding = scan_text(VALID_TCKN)[0]
    assert finding.kind == "tckn"
    assert finding.confidence is Confidence.HIGH


def test_clean_text_yields_nothing() -> None:
    assert scan_text("burada bir sey yok\nikinci satir\n") == []


# --------------------------------------------------------------------------- #
# scan_file
# --------------------------------------------------------------------------- #


def test_scans_a_file(tmp_path: Path) -> None:
    target = write(tmp_path / "app.log", f"giris basarili {VALID_TCKN}\n")
    findings = scan_file(target)
    assert [f.kind for f in findings] == ["tckn"]


def test_binary_files_are_skipped(tmp_path: Path) -> None:
    target = tmp_path / "blob.bin"
    target.write_bytes(b"\x00\x01" + VALID_TCKN.encode())
    assert scan_file(target) == []


def test_undecodable_bytes_do_not_abort_the_scan(tmp_path: Path) -> None:
    target = tmp_path / "mixed.log"
    target.write_bytes(f"gecerli {VALID_TCKN}\n".encode() + b"\xff\xfe bozuk\n")
    assert len(scan_file(target)) == 1


def test_display_path_overrides_the_reported_name(tmp_path: Path) -> None:
    target = write(tmp_path / "app.log", VALID_TCKN)
    assert scan_file(target, display_path="logs/app.log")[0].path == "logs/app.log"


# --------------------------------------------------------------------------- #
# scan_path
# --------------------------------------------------------------------------- #


def test_walks_a_directory(tmp_path: Path) -> None:
    write(tmp_path / "a.log", VALID_TCKN)
    write(tmp_path / "nested" / "b.log", VALID_TCKN)

    result = scan_path(tmp_path)
    assert len(result) == 2
    assert result.files_scanned == 2


def test_paths_are_reported_relative_to_the_root(tmp_path: Path) -> None:
    write(tmp_path / "nested" / "b.log", VALID_TCKN)
    assert scan_path(tmp_path).findings[0].path == "nested/b.log"


@pytest.mark.parametrize("noisy", [".git", "node_modules", "__pycache__", ".venv"])
def test_generated_directories_are_excluded(tmp_path: Path, noisy: str) -> None:
    write(tmp_path / noisy / "leak.log", VALID_TCKN)
    assert len(scan_path(tmp_path)) == 0


def test_extra_excludes_are_honoured(tmp_path: Path) -> None:
    write(tmp_path / "keep.log", VALID_TCKN)
    write(tmp_path / "skip.log", VALID_TCKN)

    result = scan_path(tmp_path, excludes=[*DEFAULT_EXCLUDES, "skip.log"])
    assert [f.path for f in result.findings] == ["keep.log"]


def test_scanning_a_single_file_works(tmp_path: Path) -> None:
    target = write(tmp_path / "a.log", VALID_TCKN)
    assert len(scan_path(target)) == 1


def test_empty_directory_is_clean(tmp_path: Path) -> None:
    result = scan_path(tmp_path)
    assert not result
    assert result.files_scanned == 0


def test_iter_files_is_deterministic(tmp_path: Path) -> None:
    for name in ("c.log", "a.log", "b.log"):
        write(tmp_path / name, "x")
    assert [p.name for p in iter_files(tmp_path)] == ["a.log", "b.log", "c.log"]


# --------------------------------------------------------------------------- #
# ScanResult aggregation
# --------------------------------------------------------------------------- #


def test_summary_counts(tmp_path: Path) -> None:
    write(tmp_path / "a.log", f"{VALID_TCKN}\nali@ornek.com\n")
    write(tmp_path / "b.log", "veli@ornek.com\n")

    result = scan_path(tmp_path)
    assert result.by_kind() == {"email": 2, "tckn": 1}
    assert result.by_confidence()[Confidence.HIGH] == 1
    assert set(result.by_file()) == {"a.log", "b.log"}
    assert result.worst() is Confidence.HIGH
    assert bool(result) is True


def test_worst_is_none_when_clean(tmp_path: Path) -> None:
    result = scan_path(tmp_path)
    assert result.worst() is None
    assert bool(result) is False


# --------------------------------------------------------------------------- #
# ignore markers — the difference between a scanner people keep and one they
# switch off after the first false positive on a test fixture
# --------------------------------------------------------------------------- #


def test_inline_marker_skips_the_line() -> None:
    text = f"gercek {VALID_TCKN}\nfixture {VALID_TCKN}  # kvkk: ignore\n"
    findings = scan_text(text)

    assert len(findings) == 1
    assert findings[0].line == 1


def test_inline_marker_works_with_any_comment_character() -> None:
    assert scan_text(f"INSERT ... {VALID_TCKN} -- kvkk: ignore") == []
    assert scan_text(f"value: {VALID_TCKN}  # kvkk: ignore") == []
    assert scan_text(f"const x = '{VALID_TCKN}' // kvkk: ignore") == []


def test_file_marker_skips_the_whole_file() -> None:
    text = f"# kvkk: ignore-file\n{VALID_TCKN}\n{VALID_TCKN}\n"
    assert scan_text(text) == []


def test_file_marker_is_only_honoured_near_the_top() -> None:
    text = "\n" * 20 + f"# kvkk: ignore-file\n{VALID_TCKN}\n"
    assert len(scan_text(text)) == 1


def test_file_marker_does_not_match_the_line_marker() -> None:
    """``ignore-file`` further down must not silently act as a line ignore."""
    text = f"{VALID_TCKN}\n" * 3
    assert len(scan_text(text)) == 3


def test_ignore_file_patterns_are_applied(tmp_path: Path) -> None:
    write(tmp_path / ".kvkkignore", "# comment\n\nfixtures\n")
    write(tmp_path / "fixtures" / "seed.sql", VALID_TCKN)
    write(tmp_path / "app.log", VALID_TCKN)

    result = scan_path(tmp_path)
    assert [f.path for f in result.findings] == ["app.log"]


def test_ignore_file_accepts_trailing_slashes(tmp_path: Path) -> None:
    write(tmp_path / ".kvkkignore", "fixtures/\n")
    write(tmp_path / "fixtures" / "seed.sql", VALID_TCKN)
    assert len(scan_path(tmp_path)) == 0


def test_ignore_file_covers_nested_directory_paths(tmp_path: Path) -> None:
    write(tmp_path / ".kvkkignore", "src/generated\n")
    write(tmp_path / "src" / "generated" / "data.py", VALID_TCKN)
    write(tmp_path / "src" / "app.py", VALID_TCKN)

    result = scan_path(tmp_path)
    assert [f.path for f in result.findings] == ["src/app.py"]


def test_ignore_file_can_be_turned_off(tmp_path: Path) -> None:
    write(tmp_path / ".kvkkignore", "fixtures\n")
    write(tmp_path / "fixtures" / "seed.sql", VALID_TCKN)

    assert len(scan_path(tmp_path, use_ignore_file=False)) == 1


def test_missing_ignore_file_is_not_an_error(tmp_path: Path) -> None:
    write(tmp_path / "app.log", VALID_TCKN)
    assert len(scan_path(tmp_path)) == 1


def test_by_kind_is_sorted_by_frequency(tmp_path: Path) -> None:
    write(tmp_path / "a.log", "a@x.com\nb@x.com\n" + VALID_TCKN)
    assert list(scan_path(tmp_path).by_kind()) == ["email", "tckn"]
