"""Command line interface.

    kvkk scan .                     what personal data is in this repository?
    kvkk mask app.log               hand a log to someone safely
    kvkk check 10000000146          what is this value, and is it real?

``scan`` exits non-zero when it finds something at or above ``--fail-on``,
which is what makes it usable as a pre-commit hook or a CI gate.
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import typer

from . import __version__
from .detectors import DETECTORS, detect, label_for
from .mask import Strategy, generate_salt, mask_text
from .models import Confidence, ScanResult
from .report import (
    exit_code_for,
    render_html,
    render_json,
    render_terminal,
    supports_colour,
)
from .scan import DEFAULT_EXCLUDES, scan_path

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Find and mask Turkish personal data (TCKN, IBAN, VKN, cards, phones).",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"kvkk {__version__}")
        raise typer.Exit()


@app.callback()
def _main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Find and mask Turkish personal data."""


def _parse_kinds(only: str | None) -> list[str] | None:
    if not only:
        return None

    kinds = [part.strip() for part in only.split(",") if part.strip()]
    unknown = [kind for kind in kinds if kind not in DETECTORS]
    if unknown:
        known = ", ".join(DETECTORS)
        typer.secho(
            f"unknown detector: {', '.join(unknown)}\navailable: {known}",
            fg=typer.colors.RED,
            err=True,
        )
        raise typer.Exit(code=2)
    return kinds


def _resolve_salt(salt: str | None, strategy: Strategy) -> str:
    """Warn loudly when a deterministic strategy is handed a random salt."""
    if salt:
        return salt

    if strategy in (Strategy.HASH, Strategy.FAKE):
        generated = generate_salt()
        typer.secho(
            "no --salt given, using a random one: masking will not be reproducible "
            "across runs. Pass --salt (or set KVKK_SALT) to keep values stable.",
            fg=typer.colors.YELLOW,
            err=True,
        )
        return generated

    return ""


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #


@app.command()
def scan(
    paths: list[Path] = typer.Argument(
        None, help="Files or directories to scan. Defaults to the current directory."
    ),
    only: str = typer.Option(None, "--only", help="Comma-separated detectors, e.g. 'tckn,iban'."),
    min_confidence: Confidence = typer.Option(
        Confidence.LOW, "--min-confidence", "-c", help="Drop weaker readings."
    ),
    fail_on: Confidence = typer.Option(
        None, "--fail-on", help="Exit 1 when a finding reaches this level. For CI."
    ),
    exclude: list[str] = typer.Option(
        None, "--exclude", "-x", help="Extra glob to skip. Repeatable."
    ),
    as_json: bool = typer.Option(False, "--json", help="Machine-readable output."),
    html_out: Path = typer.Option(
        None, "--html", help="Also write a self-contained HTML report here."
    ),
    limit: int = typer.Option(0, "--limit", help="Max findings shown per file (0 = all)."),
    no_ignore_file: bool = typer.Option(
        False, "--no-ignore-file", help="Ignore .kvkkignore and scan everything."
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable ANSI colour."),
) -> None:
    """Report personal data found in files or directories."""
    targets = paths or [Path.cwd()]
    kinds = _parse_kinds(only)
    excludes = list(DEFAULT_EXCLUDES) + list(exclude or [])

    combined = ScanResult()
    for target in targets:
        if not target.exists():
            typer.secho(f"no such path: {target}", fg=typer.colors.RED, err=True)
            raise typer.Exit(code=2)

        result = scan_path(
            target,
            kinds=kinds,
            min_confidence=min_confidence,
            excludes=excludes,
            use_ignore_file=not no_ignore_file,
        )
        combined.findings.extend(result.findings)
        combined.files_scanned += result.files_scanned
        combined.files_skipped += result.files_skipped
        combined.bytes_scanned += result.bytes_scanned

    if html_out:
        html_out.write_text(render_html(combined), encoding="utf-8")

    if as_json:
        typer.echo(render_json(combined))
    else:
        colour = False if no_color else supports_colour()
        typer.echo(render_terminal(combined, colour=colour, limit=limit))
        if html_out:
            typer.secho(f"\nHTML report written to {html_out}", fg=typer.colors.BLUE)

    raise typer.Exit(code=exit_code_for(combined, fail_on))


# --------------------------------------------------------------------------- #
# mask
# --------------------------------------------------------------------------- #


@app.command()
def mask(
    file: Path = typer.Argument(None, help="File to mask. Reads stdin when omitted."),
    strategy: Strategy = typer.Option(
        Strategy.PARTIAL, "--strategy", "-s", help="How to rewrite each value."
    ),
    salt: str = typer.Option(
        None,
        "--salt",
        envvar="KVKK_SALT",
        help="Secret for hash/fake. Same salt means same output.",
    ),
    only: str = typer.Option(None, "--only", help="Comma-separated detectors."),
    min_confidence: Confidence = typer.Option(
        Confidence.LOW, "--min-confidence", "-c", help="Drop weaker readings."
    ),
    in_place: bool = typer.Option(False, "--in-place", "-i", help="Rewrite the file."),
    output: Path = typer.Option(None, "--output", "-o", help="Write here instead of stdout."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Do not print the summary."),
) -> None:
    """Mask personal data in a file or on stdin."""
    kinds = _parse_kinds(only)
    key = _resolve_salt(salt, strategy)

    if in_place and file is None:
        typer.secho("--in-place needs a file", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)
    if in_place and output:
        typer.secho("--in-place and --output are mutually exclusive", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    if file is not None and not file.is_file():
        typer.secho(f"no such file: {file}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2)

    source = (
        file.read_text(encoding="utf-8", errors="replace") if file is not None else sys.stdin.read()
    )

    masked, matches = mask_text(
        source,
        strategy=strategy,
        kinds=kinds,
        min_confidence=min_confidence,
        salt=key,
    )

    if in_place:
        _write_atomic(file, masked)
    elif output:
        output.write_text(masked, encoding="utf-8")
    else:
        sys.stdout.write(masked)

    if not quiet and (in_place or output):
        counts: dict[str, int] = {}
        for match in matches:
            counts[match.kind] = counts.get(match.kind, 0) + 1
        detail = ", ".join(f"{count} {kind}" for kind, count in sorted(counts.items()))
        typer.secho(
            f"masked {len(matches)} values" + (f" ({detail})" if detail else ""),
            fg=typer.colors.GREEN,
            err=True,
        )


def _write_atomic(path: Path, content: str) -> None:
    """Write via a temporary file in the same directory, then replace.

    An interrupted in-place mask must not leave a half-masked file behind: the
    original either survives intact or is replaced by the complete result.
    """
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, suffix=".kvkk-tmp")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


# --------------------------------------------------------------------------- #
# check / kinds
# --------------------------------------------------------------------------- #


@app.command()
def check(value: str = typer.Argument(..., help="A single value to identify.")) -> None:
    """Say what a value is and whether it passes its checksum."""
    matches = detect(value)

    if not matches:
        typer.secho("not recognised as personal data", fg=typer.colors.GREEN)
        raise typer.Exit(code=1)

    for match in matches:
        colour = {
            Confidence.HIGH: typer.colors.RED,
            Confidence.MEDIUM: typer.colors.YELLOW,
            Confidence.LOW: typer.colors.CYAN,
        }[match.confidence]
        typer.secho(
            f"{label_for(match.kind)}  [{match.confidence.value}]  {match.value}",
            fg=colour,
        )


@app.command()
def kinds() -> None:
    """List every detector."""
    width = max(len(kind) for kind in DETECTORS)
    for kind, detector in DETECTORS.items():
        verified = "checksum" if detector.validator else "pattern"
        context = ", needs context" if detector.context else ""
        typer.echo(f"{kind.ljust(width)}  {detector.label}  ({verified}{context})")


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
