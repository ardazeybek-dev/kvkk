"""kvkk — find and mask Turkish personal data.

>>> from kvkk import scan_text, mask_text
>>> scan_text("müşteri 10000000146")[0].kind
'tckn'
>>> mask_text("müşteri 10000000146")[0]
'müşteri 100******46'
"""

from __future__ import annotations

__version__ = "0.1.1"

from .detectors import (
    DETECTORS,
    available_kinds,
    detect,
    is_valid_credit_card,
    is_valid_vkn,
    label_for,
)
from .mask import Strategy, generate_salt, mask_text, mask_value
from .models import Confidence, Finding, Match, ScanResult
from .report import render_html, render_json, render_terminal
from .scan import DEFAULT_EXCLUDES, scan_file, scan_path, scan_text

__all__ = [
    "DEFAULT_EXCLUDES",
    "DETECTORS",
    "Confidence",
    "Finding",
    "Match",
    "ScanResult",
    "Strategy",
    "__version__",
    "available_kinds",
    "detect",
    "generate_salt",
    "is_valid_credit_card",
    "is_valid_vkn",
    "label_for",
    "mask_text",
    "mask_value",
    "render_html",
    "render_json",
    "render_terminal",
    "scan_file",
    "scan_path",
    "scan_text",
]
