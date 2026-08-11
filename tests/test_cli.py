"""CLI tests, including the exit codes that make this usable in CI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from kvkk import __version__
from kvkk.cli import app

runner = CliRunner()

VALID_TCKN = "10000000146"


def write(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


def test_scan_reports_findings(tmp_path: Path) -> None:
    write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-color"])
    assert "tckn" in result.output
    assert "a.log" in result.output


def test_scan_output_does_not_leak_the_value(tmp_path: Path) -> None:
    write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-color"])
    assert VALID_TCKN not in result.output


def test_clean_scan_exits_zero(tmp_path: Path) -> None:
    write(tmp_path / "a.log", "temiz dosya")
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-color"])
    assert result.exit_code == 0
    assert "Clean" in result.output


def test_findings_alone_do_not_fail_the_run(tmp_path: Path) -> None:
    write(tmp_path / "a.log", VALID_TCKN)
    assert runner.invoke(app, ["scan", str(tmp_path), "--no-color"]).exit_code == 0


def test_fail_on_high_exits_one(tmp_path: Path) -> None:
    write(tmp_path / "a.log", VALID_TCKN)
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high", "--no-color"])
    assert result.exit_code == 1


def test_fail_on_high_ignores_weaker_findings(tmp_path: Path) -> None:
    write(tmp_path / "a.log", "sunucu 10.0.0.1")
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "high", "--no-color"])
    assert result.exit_code == 0


def test_json_output_is_parseable(tmp_path: Path) -> None:
    write(tmp_path / "a.log", f"{VALID_TCKN}\nali@ornek.com")
    result = runner.invoke(app, ["scan", str(tmp_path), "--json"])

    payload = json.loads(result.stdout)
    assert payload["summary"]["findings"] == 2
    assert payload["summary"]["by_kind"] == {"email": 1, "tckn": 1}
    assert payload["findings"][0]["kind"] == "tckn"
    assert VALID_TCKN not in result.stdout


def test_html_report_is_written(tmp_path: Path) -> None:
    write(tmp_path / "a.log", VALID_TCKN)
    report = tmp_path / "report.html"

    runner.invoke(app, ["scan", str(tmp_path), "--html", str(report), "--no-color"])

    html = report.read_text(encoding="utf-8")
    assert html.startswith("<!doctype html>")
    assert "Turkish national ID" in html
    assert VALID_TCKN not in html


def test_only_restricts_detectors(tmp_path: Path) -> None:
    write(tmp_path / "a.log", f"{VALID_TCKN} ali@ornek.com")
    result = runner.invoke(app, ["scan", str(tmp_path), "--only", "email", "--json"])
    assert json.loads(result.stdout)["summary"]["by_kind"] == {"email": 1}


def test_unknown_detector_is_rejected(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--only", "nope"])
    assert result.exit_code == 2


def test_missing_path_is_rejected() -> None:
    result = runner.invoke(app, ["scan", "yok-boyle-bir-yer"])
    assert result.exit_code == 2


def test_exclude_is_honoured(tmp_path: Path) -> None:
    write(tmp_path / "keep.log", VALID_TCKN)
    write(tmp_path / "skip.log", VALID_TCKN)
    result = runner.invoke(app, ["scan", str(tmp_path), "-x", "skip.log", "--json"])
    assert json.loads(result.stdout)["summary"]["findings"] == 1


def test_limit_truncates_but_says_so(tmp_path: Path) -> None:
    write(tmp_path / "a.log", "\n".join([VALID_TCKN] * 5))
    result = runner.invoke(app, ["scan", str(tmp_path), "--limit", "2", "--no-color"])
    assert "3 more" in result.output


# --------------------------------------------------------------------------- #
# mask
# --------------------------------------------------------------------------- #


def test_mask_reads_stdin() -> None:
    result = runner.invoke(app, ["mask"], input=f"musteri {VALID_TCKN}\n")
    assert "100******46" in result.output
    assert VALID_TCKN not in result.output


def test_mask_writes_a_file(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    target = tmp_path / "clean.log"

    runner.invoke(app, ["mask", str(source), "-o", str(target)])
    assert target.read_text(encoding="utf-8") == "musteri 100******46"


def test_mask_in_place(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    result = runner.invoke(app, ["mask", str(source), "-i"])

    assert result.exit_code == 0
    assert source.read_text(encoding="utf-8") == "musteri 100******46"


def test_in_place_needs_a_file() -> None:
    result = runner.invoke(app, ["mask", "-i"], input="x")
    assert result.exit_code == 2


def test_in_place_and_output_conflict(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", "x")
    result = runner.invoke(app, ["mask", str(source), "-i", "-o", str(tmp_path / "b.log")])
    assert result.exit_code == 2


def test_mask_rejects_a_missing_file() -> None:
    assert runner.invoke(app, ["mask", "yok.log"]).exit_code == 2


def test_redact_strategy(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    target = tmp_path / "clean.log"

    runner.invoke(app, ["mask", str(source), "-s", "redact", "-o", str(target)])
    assert target.read_text(encoding="utf-8") == "musteri [TCKN]"


def test_fake_strategy_is_stable_across_runs(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    outputs = []

    for name in ("one.log", "two.log"):
        target = tmp_path / name
        runner.invoke(app, ["mask", str(source), "-s", "fake", "--salt", "k", "-o", str(target)])
        outputs.append(target.read_text(encoding="utf-8"))

    assert outputs[0] == outputs[1]
    assert VALID_TCKN not in outputs[0]


def test_salt_can_come_from_the_environment(tmp_path: Path) -> None:
    source = write(tmp_path / "a.log", f"musteri {VALID_TCKN}")
    target = tmp_path / "clean.log"

    runner.invoke(
        app,
        ["mask", str(source), "-s", "hash", "-o", str(target)],
        env={"KVKK_SALT": "from-env"},
    )
    assert "tckn_" in target.read_text(encoding="utf-8")


# --------------------------------------------------------------------------- #
# check / kinds / version
# --------------------------------------------------------------------------- #


def test_check_identifies_a_value() -> None:
    result = runner.invoke(app, ["check", VALID_TCKN])
    assert result.exit_code == 0
    assert "Turkish national ID" in result.output


def test_check_exits_one_for_ordinary_text() -> None:
    result = runner.invoke(app, ["check", "12345678901"])
    assert result.exit_code == 1
    assert "not recognised" in result.output


def test_kinds_lists_every_detector() -> None:
    result = runner.invoke(app, ["kinds"])
    for kind in ("tckn", "iban", "vkn", "credit_card", "phone", "email", "plate", "ip"):
        assert kind in result.output


def test_kinds_marks_checksum_backed_detectors() -> None:
    result = runner.invoke(app, ["kinds"])
    assert "checksum" in result.output
    assert "needs context" in result.output


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert __version__ in result.output


def test_bare_invocation_shows_help() -> None:
    result = runner.invoke(app, [])
    assert "scan" in result.output
    assert "mask" in result.output
