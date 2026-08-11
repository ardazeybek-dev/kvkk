"""Run every docstring example, so the documentation cannot drift from the code."""

from __future__ import annotations

import doctest
import importlib

import pytest

MODULES = ["kvkk", "kvkk.detectors", "kvkk.mask", "kvkk.models", "kvkk.report", "kvkk.scan"]


@pytest.mark.parametrize("name", MODULES)
def test_docstring_examples(name: str) -> None:
    module = importlib.import_module(name)
    result = doctest.testmod(module, verbose=False)
    assert result.failed == 0, f"{result.failed} doctest failure(s) in {name}"
