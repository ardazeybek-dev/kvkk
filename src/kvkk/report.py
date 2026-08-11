"""Turn a :class:`~kvkk.models.ScanResult` into something a person can act on.

Three renderers, three audiences: the terminal for the developer who just ran
the scan, JSON for the pipeline that has to decide whether to fail the build,
and a single self-contained HTML file for the colleague who has to be convinced
there is a problem at all.

None of them print a raw personal-data value. Excerpts arrive already masked
from :mod:`kvkk.scan`, and no renderer has access to the original.
"""

from __future__ import annotations

import html
import json
import os
import sys
from collections.abc import Sequence

from .detectors import label_for
from .models import Confidence, Finding, ScanResult

__all__ = ["render_html", "render_json", "render_terminal", "supports_colour"]

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"

_COLOUR = {
    Confidence.HIGH: "\033[31m",
    Confidence.MEDIUM: "\033[33m",
    Confidence.LOW: "\033[36m",
}

_SYMBOL = {
    Confidence.HIGH: "!",
    Confidence.MEDIUM: "?",
    Confidence.LOW: "-",
}


def supports_colour(stream: object | None = None) -> bool:
    """Whether ANSI colour should be used, honouring ``NO_COLOR``."""
    if os.environ.get("NO_COLOR"):
        return False
    target = stream if stream is not None else sys.stdout
    return bool(getattr(target, "isatty", lambda: False)())


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{_RESET}" if enabled else text


def _plural(count: int, singular: str, plural: str | None = None) -> str:
    return singular if count == 1 else (plural or f"{singular}s")


# --------------------------------------------------------------------------- #
# terminal
# --------------------------------------------------------------------------- #


def render_terminal(result: ScanResult, colour: bool | None = None, limit: int = 0) -> str:
    """Render findings grouped by file, then a summary line.

    ``limit`` caps the number of findings printed per file; the count of what
    was hidden is always stated, because a report that silently truncates reads
    as "that's all of it".
    """
    use_colour = supports_colour() if colour is None else colour

    if not result.findings:
        scanned = f"{result.files_scanned} {_plural(result.files_scanned, 'file')}"
        return _paint(f"Clean — no personal data found in {scanned}.", _BOLD, use_colour)

    lines: list[str] = []

    for path, findings in result.by_file().items():
        lines.append(_paint(path, _BOLD, use_colour))

        shown = findings[:limit] if limit else findings
        for finding in shown:
            lines.append(_format_finding(finding, use_colour))

        hidden = len(findings) - len(shown)
        if hidden:
            lines.append(_paint(f"    … {hidden} more in this file", _DIM, use_colour))

        lines.append("")

    lines.extend(_summary_lines(result, use_colour))
    return "\n".join(lines)


def _format_finding(finding: Finding, colour: bool) -> str:
    level = finding.confidence
    marker = _paint(_SYMBOL[level], _COLOUR[level], colour)
    location = _paint(f"{finding.line}:{finding.column}", _DIM, colour)
    kind = _paint(finding.kind, _COLOUR[level], colour)
    return f"  {marker} {location}  {kind}  {finding.excerpt}"


def _summary_lines(result: ScanResult, colour: bool) -> list[str]:
    total = len(result.findings)
    by_confidence = result.by_confidence()

    breakdown = "  ".join(
        _paint(f"{by_confidence[level]} {level.value}", _COLOUR[level], colour)
        for level in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
        if by_confidence[level]
    )

    kinds = ", ".join(f"{kind} ×{count}" for kind, count in result.by_kind().items())

    lines = [
        _paint(
            f"{total} {_plural(total, 'finding')} in "
            f"{len(result.by_file())} of {result.files_scanned} "
            f"{_plural(result.files_scanned, 'file')}",
            _BOLD,
            colour,
        ),
        f"  {breakdown}",
        _paint(f"  {kinds}", _DIM, colour),
    ]

    if result.files_skipped:
        lines.append(_paint(f"  {result.files_skipped} unreadable, skipped", _DIM, colour))

    return lines


# --------------------------------------------------------------------------- #
# json
# --------------------------------------------------------------------------- #


def render_json(result: ScanResult, indent: int = 2) -> str:
    """Machine-readable report. Stable keys; no raw values."""
    payload = {
        "summary": {
            "findings": len(result.findings),
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "files_affected": len(result.by_file()),
            "bytes_scanned": result.bytes_scanned,
            "by_kind": result.by_kind(),
            "by_confidence": {
                level.value: count for level, count in result.by_confidence().items()
            },
        },
        "findings": [
            {
                "path": finding.path,
                "line": finding.line,
                "column": finding.column,
                "kind": finding.kind,
                "label": label_for(finding.kind),
                "confidence": finding.confidence.value,
                "excerpt": finding.excerpt,
            }
            for finding in result.findings
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=indent)


# --------------------------------------------------------------------------- #
# html
# --------------------------------------------------------------------------- #

_CSS = """
*, *::before, *::after { box-sizing: border-box; }
:root {
  --bg: #fbfbfa; --panel: #ffffff; --ink: #1a1a19; --muted: #6b6b68;
  --line: #e4e4e1; --high: #b4232a; --medium: #9a6410; --low: #2b6a8f;
  --high-bg: #fdeceb; --medium-bg: #fdf3e2; --low-bg: #eaf3f8;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #17181a; --panel: #1e2023; --ink: #e8e8e6; --muted: #9a9a96;
    --line: #2e3135; --high: #ff8a84; --medium: #e8b56a; --low: #79c0e8;
    --high-bg: #35201f; --medium-bg: #322718; --low-bg: #1b2b35;
  }
}
body {
  margin: 0; padding: 2.5rem 1.25rem 4rem;
  background: var(--bg); color: var(--ink);
  font: 15px/1.6 ui-sans-serif, -apple-system, "Segoe UI", Roboto, sans-serif;
}
.wrap { max-width: 62rem; margin: 0 auto; }
h1 { font-size: 1.6rem; margin: 0 0 .25rem; letter-spacing: -.01em; }
.sub { color: var(--muted); margin: 0 0 2rem; }
.cards {
  display: grid; gap: .75rem; margin-bottom: 2rem;
  grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr));
}
.card {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: .6rem; padding: 1rem;
}
.card .n { font-size: 1.9rem; font-weight: 650; line-height: 1.1; }
.card .l {
  color: var(--muted); font-size: .82rem;
  text-transform: uppercase; letter-spacing: .04em;
}
.card.high .n { color: var(--high); }
.card.medium .n { color: var(--medium); }
.card.low .n { color: var(--low); }
.file {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: .6rem; margin-bottom: 1rem; overflow: hidden;
}
.file > summary {
  cursor: pointer; padding: .85rem 1rem; font-weight: 600; display: flex;
  justify-content: space-between; gap: 1rem; align-items: center;
}
.file > summary::-webkit-details-marker { display: none; }
.path {
  font-family: ui-monospace, "Cascadia Code", Consolas, monospace;
  font-size: .88rem; word-break: break-all;
}
.count {
  color: var(--muted); font-weight: 400; font-size: .85rem; white-space: nowrap;
}
.rows { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .88rem; }
td { padding: .5rem 1rem; border-top: 1px solid var(--line); vertical-align: top; }
td.loc {
  font-family: ui-monospace, Consolas, monospace; color: var(--muted);
  white-space: nowrap; width: 1%;
}
td.kind { white-space: nowrap; width: 1%; }
td.ex { font-family: ui-monospace, Consolas, monospace; word-break: break-word; }
.tag {
  display: inline-block; padding: .1rem .5rem; border-radius: 1rem;
  font-size: .76rem; font-weight: 600;
}
.tag.high { background: var(--high-bg); color: var(--high); }
.tag.medium { background: var(--medium-bg); color: var(--medium); }
.tag.low { background: var(--low-bg); color: var(--low); }
footer {
  color: var(--muted); font-size: .82rem; margin-top: 2.5rem;
  border-top: 1px solid var(--line); padding-top: 1rem;
}
.clean {
  background: var(--panel); border: 1px solid var(--line);
  border-radius: .6rem; padding: 2.5rem; text-align: center;
}
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def render_html(result: ScanResult, title: str = "KVKK scan report", subtitle: str = "") -> str:
    """A single self-contained HTML file: no network, no assets, no scripts."""
    if not result.findings:
        body = (
            '<div class="clean"><h2>Clean</h2>'
            f"<p>No personal data found in {result.files_scanned} "
            f"{_plural(result.files_scanned, 'file')}.</p></div>"
        )
    else:
        body = _html_cards(result) + _html_files(result)

    note = _esc(subtitle) if subtitle else "Every value below is already masked."

    return (
        "<!doctype html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head>"
        f'<body><div class="wrap"><h1>{_esc(title)}</h1>'
        f'<p class="sub">{note}</p>{body}'
        "<footer>Generated by kvkk — checksum-verified detection, "
        "masked excerpts. A finding is evidence to review, not proof of a breach."
        "</footer></div></body></html>"
    )


def _html_cards(result: ScanResult) -> str:
    by_confidence = result.by_confidence()
    cards = [("", len(result.findings), "findings"), ("", len(result.by_file()), "files affected")]
    cards += [
        (level.value, by_confidence[level], level.value)
        for level in (Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW)
        if by_confidence[level]
    ]

    rendered = "".join(
        f'<div class="card {css}"><div class="n">{count}</div>'
        f'<div class="l">{_esc(label)}</div></div>'
        for css, count, label in cards
    )
    return f'<div class="cards">{rendered}</div>'


def _html_files(result: ScanResult) -> str:
    blocks: list[str] = []

    for path, findings in result.by_file().items():
        rows = "".join(
            f'<tr><td class="loc">{f.line}:{f.column}</td>'
            f'<td class="kind"><span class="tag {f.confidence.value}">'
            f"{_esc(label_for(f.kind))}</span></td>"
            f'<td class="ex">{_esc(f.excerpt)}</td></tr>'
            for f in findings
        )
        count = f"{len(findings)} {_plural(len(findings), 'finding')}"
        blocks.append(
            f'<details class="file" open><summary>'
            f'<span class="path">{_esc(path)}</span>'
            f'<span class="count">{count}</span></summary>'
            f'<div class="rows"><table>{rows}</table></div></details>'
        )

    return "".join(blocks)


def exit_code_for(result: ScanResult, fail_on: Confidence | None) -> int:
    """``1`` when the scan found something at or above ``fail_on``, else ``0``."""
    if fail_on is None:
        return 0

    ranks = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
    threshold = ranks[fail_on]
    return 1 if any(ranks[f.confidence] >= threshold for f in result.findings) else 0


def summarise(result: ScanResult, kinds: Sequence[str] | None = None) -> str:
    """One-line summary, used for CI annotations and commit hooks."""
    if not result.findings:
        return "kvkk: clean"

    parts = ", ".join(f"{count} {kind}" for kind, count in result.by_kind().items())
    return f"kvkk: {len(result.findings)} findings ({parts})"
