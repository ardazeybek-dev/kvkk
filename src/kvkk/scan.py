"""Walk files and directories looking for personal data.

Two decisions worth knowing about:

*The report never repeats the leak.* Every excerpt is partially masked before
it is stored, so a scan report can be pasted into a ticket without becoming the
second copy of the incident. There is no flag to turn that off.

*Files are read line by line.* A ten-gigabyte log is scanned in constant
memory, and a match keeps its line and column so an editor can jump to it.

*Some valid identifiers belong to nobody.* Every codebase has test fixtures and
documentation examples with real check digits, and a scanner that cannot be
told about them is a scanner that gets switched off. Two ways to say so:
a ``.kvkkignore`` file of globs at the root of the scan, and a ``kvkk: ignore``
comment on a single line.
"""

from __future__ import annotations

import contextlib
import fnmatch
import re
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path

from .detectors import detect
from .mask import Strategy, mask_value
from .models import Confidence, Finding, Match, ScanResult

__all__ = [
    "DEFAULT_EXCLUDES",
    "IGNORE_FILENAME",
    "iter_files",
    "load_ignore_patterns",
    "scan_file",
    "scan_path",
    "scan_text",
]

#: Directories and files that are never worth scanning: they hold generated or
#: vendored content, and reporting on them buries the findings that matter.
DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    "*.egg-info",
    ".tox",
    "target",
    "vendor",
    "*.min.js",
    "*.min.css",
    "*.lock",
    "package-lock.json",
)

#: A file of glob patterns, one per line, read from the root of the scan.
IGNORE_FILENAME = ".kvkkignore"

_BINARY_PROBE_BYTES = 8192
_EXCERPT_RADIUS = 40

# ``kvkk: ignore`` skips the line it appears on; ``kvkk: ignore-file`` skips the
# whole file when it appears in the first few lines. The comment character does
# not matter — only the marker is looked for — so the same spelling works in
# Python, YAML, SQL and JavaScript.
_IGNORE_FILE_MARKER = re.compile(r"kvkk:\s*ignore-file\b", re.I)
_IGNORE_LINE_MARKER = re.compile(r"kvkk:\s*ignore\b(?!-)", re.I)

_IGNORE_HEADER_LINES = 10


def load_ignore_patterns(root: Path) -> list[str]:
    """Read ``.kvkkignore`` from ``root``, if it is there.

    Blank lines and ``#`` comments are skipped. A missing or unreadable file
    is not an error — it just means nothing extra is ignored.
    """
    location = (root if root.is_dir() else root.parent) / IGNORE_FILENAME

    try:
        raw = location.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    patterns: list[str] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            patterns.append(stripped.rstrip("/"))
    return patterns


def _is_binary(path: Path) -> bool:
    """Treat a file as binary when its first block contains a NUL byte."""
    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True


def _is_excluded(path: Path, patterns: Sequence[str], root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        relative = path

    parts = relative.parts
    as_posix = str(relative).replace("\\", "/")

    for pattern in patterns:
        if any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
        if fnmatch.fnmatch(as_posix, pattern):
            return True
        # A directory pattern covers everything beneath it: "src/kvkk" hides
        # "src/kvkk/scan.py" without needing a trailing wildcard.
        if as_posix == pattern or as_posix.startswith(f"{pattern}/"):
            return True
    return False


def iter_files(
    root: Path,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    follow_symlinks: bool = False,
) -> Iterator[Path]:
    """Yield every scannable file under ``root``, in a stable order.

    A file path is yielded as-is; a directory is walked recursively with
    ``excludes`` applied to each path component.
    """
    if root.is_file():
        yield root
        return

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if not follow_symlinks and path.is_symlink():
            continue
        if _is_excluded(path, excludes, root):
            continue
        yield path


def _excerpts(line: str, targets: Sequence[Match], maskable: Sequence[Match]) -> list[str]:
    """One masked window per target, sharing a single rewrite of the line.

    ``maskable`` is everything on the line that could be masked; ``targets``
    is the subset actually being reported, and the returned windows are
    centred on those. The two differ whenever a filter is in play: a CSV row
    holds a national ID *and* a phone number, and ``--min-confidence high``
    drops the phone from the report — it must not put it back in plain text in
    the national ID's excerpt. Narrowing the report never widens what it
    exposes.
    """
    pieces: list[str] = []
    positions: dict[tuple[int, int], tuple[int, int]] = {}
    cursor = 0
    length = 0

    for match in maskable:
        gap = line[cursor : match.start]
        pieces.append(gap)
        length += len(gap)

        masked = mask_value(match, Strategy.PARTIAL)
        positions[(match.start, match.end)] = (length, len(masked))
        pieces.append(masked)
        length += len(masked)

        cursor = match.end

    pieces.append(line[cursor:])
    rebuilt = "".join(pieces)

    return [_window(rebuilt, *positions[(t.start, t.end)]) for t in targets]


def _window(text: str, start: int, size: int) -> str:
    """A short slice of ``text`` centred on ``start``, elided at both ends."""
    left = max(0, start - _EXCERPT_RADIUS)
    right = min(len(text), start + size + _EXCERPT_RADIUS)

    prefix = "…" if left > 0 else ""
    suffix = "…" if right < len(text) else ""
    return f"{prefix}{text[left:right].strip()}{suffix}"


def scan_text(
    text: str,
    path: str = "<text>",
    kinds: Sequence[str] | None = None,
    min_confidence: Confidence = Confidence.LOW,
) -> list[Finding]:
    """Scan an in-memory string and locate each match by line and column.

    >>> findings = scan_text("a\\nTCKN 10000000146\\n")
    >>> findings[0].line, findings[0].kind
    (2, 'tckn')
    """
    return _scan_lines(text.splitlines(), path, kinds, min_confidence)


def _scan_lines(
    lines: Iterable[str],
    path: str,
    kinds: Sequence[str] | None,
    min_confidence: Confidence,
) -> list[Finding]:
    """Scan an iterable of lines, honouring the inline ignore markers."""
    findings: list[Finding] = []

    for number, line in enumerate(lines, start=1):
        if number <= _IGNORE_HEADER_LINES and _IGNORE_FILE_MARKER.search(line):
            return []
        if _IGNORE_LINE_MARKER.search(line):
            continue

        reported = detect(line, kinds=kinds, min_confidence=min_confidence)
        if not reported:
            continue

        maskable = _maskable_for(line, reported, kinds, min_confidence)
        findings.extend(_findings_for(path, number, line, reported, maskable))

    return findings


def _maskable_for(
    line: str,
    reported: Sequence[Match],
    kinds: Sequence[str] | None,
    min_confidence: Confidence,
) -> list[Match]:
    """Everything on the line that should be masked in an excerpt.

    Without a filter this is exactly what is being reported. With one, the
    unreported matches are added back — they are not findings, but they are
    still personal data, and an excerpt must not print them.
    """
    if kinds is None and min_confidence is Confidence.LOW:
        return list(reported)

    combined = list(reported)
    combined.extend(
        match
        for match in detect(line)
        if not any(match.start < t.end and t.start < match.end for t in reported)
    )
    combined.sort(key=lambda match: match.start)
    return combined


def _findings_for(
    path: str,
    line_number: int,
    line: str,
    targets: Sequence[Match],
    maskable: Sequence[Match],
) -> list[Finding]:
    if not targets:
        return []

    excerpts = _excerpts(line, targets, maskable)
    return [
        Finding(
            path=path,
            line=line_number,
            column=match.start + 1,
            match=match,
            excerpt=excerpt,
        )
        for match, excerpt in zip(targets, excerpts, strict=True)
    ]


def scan_file(
    path: Path,
    kinds: Sequence[str] | None = None,
    min_confidence: Confidence = Confidence.LOW,
    display_path: str | None = None,
) -> list[Finding]:
    """Scan one file, streaming it a line at a time.

    Binary files yield nothing. Undecodable bytes are replaced rather than
    raising, because a log file with one bad byte is still worth scanning.
    """
    if _is_binary(path):
        return []

    name = display_path if display_path is not None else str(path)

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        stripped = (line.rstrip("\n").rstrip("\r") for line in handle)
        return _scan_lines(stripped, name, kinds, min_confidence)


def scan_path(
    root: Path,
    kinds: Sequence[str] | None = None,
    min_confidence: Confidence = Confidence.LOW,
    excludes: Sequence[str] = DEFAULT_EXCLUDES,
    relative_to: Path | None = None,
    use_ignore_file: bool = True,
) -> ScanResult:
    """Scan a file or a whole directory tree.

    Unreadable files are counted as skipped rather than aborting the run: a
    scan that dies halfway through a directory is worse than one that reports
    what it could not open.

    Patterns from ``.kvkkignore`` at the root are added to ``excludes`` unless
    ``use_ignore_file`` is off.
    """
    base = relative_to if relative_to is not None else (root if root.is_dir() else root.parent)
    patterns = list(excludes)
    if use_ignore_file:
        patterns += load_ignore_patterns(root)

    result = ScanResult()

    for path in iter_files(root, excludes=patterns):
        try:
            display = str(path.relative_to(base)).replace("\\", "/")
        except ValueError:
            display = str(path)

        try:
            findings = scan_file(
                path,
                kinds=kinds,
                min_confidence=min_confidence,
                display_path=display,
            )
        except OSError:
            result.files_skipped += 1
            continue

        with contextlib.suppress(OSError):
            result.bytes_scanned += path.stat().st_size

        result.files_scanned += 1
        result.findings.extend(findings)

    return result
