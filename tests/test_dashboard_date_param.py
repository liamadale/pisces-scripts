"""Regression tests for dashboard date parameter sanitisation (reflected XSS)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from apps.dashboard_web import safe_date_param


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("2026-01-15", "2026-01-15"),
        ("  2026-01-15  ", "2026-01-15"),
        ("", ""),
        ("  ", ""),
        ("<script>alert(1)</script>", ""),
        ("2026-99-99", ""),
        ("not-a-date", ""),
        ("2026-01-15; DROP TABLE", ""),
    ],
)
def test_safe_date_param(raw: str, expected: str) -> None:
    assert safe_date_param(raw) == expected
