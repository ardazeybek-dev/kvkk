# kvkk

[![CI](https://github.com/ardazeybek-dev/kvkk/actions/workflows/ci.yml/badge.svg)](https://github.com/ardazeybek-dev/kvkk/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/kvkk.svg)](https://pypi.org/project/kvkk/)
[![Python](https://img.shields.io/pypi/pyversions/kvkk.svg)](https://pypi.org/project/kvkk/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Find and mask Turkish personal data — TCKN, IBAN, VKN, payment cards, phone
numbers, licence plates — in files, logs and database dumps. Checksum-verified,
so it does not cry wolf. No network, no telemetry, no dependencies beyond
[`trkit`](https://github.com/ardazeybek-dev/trkit) and `typer`.

```bash
pip install kvkk
kvkk scan .
```

## Why

Personal data does not leak out of databases. It leaks out of the places nobody
thinks of as a database:

```
[2026-08-11 09:14:02] INFO  order.create  user=10000000146 iban=TR330006100519786457841326
```

That line is in a log file, in a `.env`, in a fixture, in a CSV someone mailed
themselves, in the JSON body of a bug report. Under KVKK it is personal data
wherever it sits — and nobody knows how many copies exist, because nobody has
ever counted.

`kvkk` counts them.

```console
$ kvkk scan .
fixtures/customers.csv
  ! 2:16  tckn  1;Ahmet Yılmaz;100******46;053*********67;İzmir
  ? 2:28  phone  1;Ahmet Yılmaz;100******46;053*********67;İzmir

logs/app.log
  ! 2:49  tckn  …order.create   user=100******46 iban=TR3*******************26 t…
  ! 2:66  iban  …create   user=100******46 iban=TR3*******************26 total=1249.90
  ! 3:49  credit_card  …DEBUG payment.charge card=411**************11 exp=12/28
  ! 4:47  phone  …INFO  sms.send       to=+90************67 template=order_ok
  ! 7:49  vkn  …INFO  invoice.issue  VKN: 454*****20 amount=1249.90

118 findings in 6 of 412 files
  94 high  21 medium  3 low
  tckn ×61, iban ×33, phone ×21, email ×3
```

Note what is *not* in that list: `order_id=12345678901` on line 5 of the same
log. Eleven digits, right shape, fails the checksum — so it is not a finding.

## It does not cry wolf

A scanner that flags every eleven-digit number gets removed from CI on day two.
Three rules keep this one quiet enough to leave switched on:

**Checksums beat regular expressions.** TCKN, IBAN, VKN and card numbers all
carry check digits. A value that fails its checksum is never reported, so an
order number does not become an incident:

```console
$ kvkk check 12345678901
not recognised as personal data

$ kvkk check 10000000146
Turkish national ID (TCKN)  [high]  10000000146
```

**Ambiguous shapes need context.** A tax ID has a single check digit, so about
one in ten arbitrary ten-digit numbers passes it. `vkn` is therefore only
reported when a nearby word — `VKN`, `vergi no`, `tax id` — agrees with the
reading.

**Everything else is graded, not dropped.** `+90 532 …` is strong evidence;
seven loose digits are not. Both are reported, at different confidence levels,
and `--min-confidence` decides what you want to see.

| detector      | verified by       | confidence |
| ------------- | ----------------- | ---------- |
| `tckn`        | checksum          | high       |
| `iban`        | ISO 13616 mod-97  | high       |
| `credit_card` | Luhn              | high       |
| `vkn`         | checksum + context| high       |
| `phone`       | pattern + prefix  | high / medium / low |
| `email`       | pattern           | medium     |
| `plate`       | pattern           | medium     |
| `ip`          | pattern           | low        |

## The report is not the second leak

Every excerpt is masked before it is written, in every format. A `kvkk` report
can be pasted into a ticket, attached to an e-mail, or committed to a repo
without becoming another copy of the data it is warning you about. There is no
flag to turn that off.

```bash
kvkk scan . --html report.html    # one self-contained file, no assets, no scripts
kvkk scan . --json                # for the pipeline
```

## Some valid identifiers belong to nobody

Every codebase has test fixtures and documentation examples with real check
digits — the `4111…` Visa test card, an IBAN copied out of a spec. A scanner
that cannot be told about them is a scanner that gets switched off in week one.

A `.kvkkignore` file at the root of the scan, globs one per line:

```
tests
fixtures/seed.sql
src/generated
```

Or a marker on a single line. The comment character does not matter, so the
same spelling works in Python, SQL, YAML and JavaScript:

```python
CUSTOMER_FIXTURE = "10000000146"  # kvkk: ignore
```

```sql
-- kvkk: ignore-file
INSERT INTO customers VALUES ('10000000146', ...);
```

`kvkk` applies this to itself: its own `.kvkkignore` covers the test suite and
the docstrings, and its CI runs `kvkk scan . --fail-on high` on every push.
`--no-ignore-file` sees through all of it.

## Four ways to mask, for four different jobs

KVKK draws a hard line between *anonymisation* — the link to a person is
destroyed — and *pseudonymisation*, where it is only hidden and the result is
still regulated personal data. Which side of that line you need depends on what
you are doing with the file.

```console
$ kvkk mask app.log --strategy partial   # 100******46   — support can still confirm it
$ kvkk mask app.log --strategy redact    # [TCKN]        — the value is gone
$ kvkk mask app.log --strategy hash      # tckn_8f2a1c   — same person, same token
$ kvkk mask app.log --strategy fake      # 29874500146   — a *valid* fake, for staging
```

`hash` and `fake` are deterministic and salted:

```bash
kvkk mask dump.sql --strategy fake --salt "$KVKK_SALT" -o staging.sql
```

The same input and salt always give the same output, so foreign keys still
join across tables and files. `fake` output passes the *real* validators — a
faked TCKN satisfies the TCKN checksum, a faked IBAN satisfies mod-97 — so a
masked staging database does not fail its own input validation. Change the
salt and the mapping is gone for good.

## In CI

`scan` exits `1` when it finds something at or above `--fail-on`, so a leak
fails the build instead of reaching production:

```yaml
- run: pip install kvkk
- run: kvkk scan . --fail-on high
```

As a pre-commit hook:

```yaml
repos:
  - repo: local
    hooks:
      - id: kvkk
        name: kvkk
        entry: kvkk scan --fail-on high
        language: system
        pass_filenames: false
```

## Library usage

```python
from kvkk import detect, mask_text, scan_path, render_html

detect("müşteri 10000000146")
# [Match(kind='tckn', value='10000000146', start=8, end=19, confidence=HIGH)]

mask_text("müşteri 10000000146")[0]
# 'müşteri 100******46'

result = scan_path(Path("logs"))
result.by_kind()  # {'tckn': 61, 'iban': 33}
result.worst()  # Confidence.HIGH
Path("report.html").write_text(render_html(result), encoding="utf-8")
```

Scanning is streamed line by line, so a ten-gigabyte log file is scanned in
constant memory.

## Command line

```
kvkk scan [PATHS]     report personal data found in files or directories
kvkk mask [FILE]      mask a file or stdin
kvkk check VALUE      say what a single value is, and whether it checks out
kvkk kinds            list every detector
```

Useful flags: `--only tckn,iban`, `--min-confidence high`, `--fail-on high`,
`--exclude '*.sql'`, `--html FILE`, `--json`, `--limit N`, `--no-ignore-file`.

## What this does not do

Being honest about the edges is part of the tool:

- **It does not find names or addresses.** Those have no checksum and no fixed
  shape, and guessing at them produces the kind of noise that gets a scanner
  switched off. Structured identifiers only.
- **A checksum is not a person.** `10000000146` is a *valid* TCKN; it is not
  necessarily anyone's. Findings are evidence to review, not proof of a breach.
- **It does not read binaries, images or PDFs.** No OCR, no archive extraction.
- **It is not legal advice.** It tells you where the data is. What you are
  obliged to do about it is a question for a lawyer.

## Development

```bash
git clone https://github.com/ardazeybek-dev/kvkk
cd kvkk
pip install -e ".[dev]"
pytest
ruff check .
```

## Licence

MIT — see [LICENSE](LICENSE).
