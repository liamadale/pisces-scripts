"""Tests for src/querier/filter_loader.py — load_filters()."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.filter_loader import load_filters


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)


# ---------------------------------------------------------------------------
# Missing directory
# ---------------------------------------------------------------------------


def test_missing_dir_returns_error(tmp_path: str) -> None:
    missing = os.path.join(str(tmp_path), "does_not_exist")
    result = load_filters(missing)
    assert result["filter_count"] == 0
    assert result["must_not"] == []
    assert any("not found" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# categories.yaml skip
# ---------------------------------------------------------------------------


def test_categories_yaml_skipped(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "categories.yaml"),
        "enabled: true\nmust_not:\n  - {term: {src_ip: '1.2.3.4'}}\n",
    )
    result = load_filters(str(tmp_path))
    assert result["filter_count"] == 0
    assert result["must_not"] == []


# ---------------------------------------------------------------------------
# enabled: false skip
# ---------------------------------------------------------------------------


def test_disabled_filter_skipped(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "skip_me.yaml"),
        "enabled: false\nmust_not:\n  - {term: {src_ip: '1.2.3.4'}}\n",
    )
    result = load_filters(str(tmp_path))
    assert result["filter_count"] == 0
    assert result["must_not"] == []


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------


def test_comment_key_stripped(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "with_comment.yaml"),
        (
            "enabled: true\n"
            "must_not:\n"
            "  - comment: 'scanner noise'\n"
            "    term:\n"
            "      src_ip: '1.2.3.4'\n"
        ),
    )
    result = load_filters(str(tmp_path))
    assert result["filter_count"] == 1
    assert len(result["must_not"]) == 1
    clause = result["must_not"][0]
    assert "comment" not in clause
    assert clause.get("term") == {"src_ip": "1.2.3.4"}


# ---------------------------------------------------------------------------
# Municipality scoping
# ---------------------------------------------------------------------------


def test_municipality_scoping_match(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "scoped.yaml"),
        (
            "enabled: true\n"
            "municipalities: ['bonney-lake', 'puyallup']\n"
            "must_not:\n"
            "  - {term: {src_ip: '10.0.0.1'}}\n"
        ),
    )
    result = load_filters(str(tmp_path), municipality="bonney-lake")
    assert result["filter_count"] == 1


def test_municipality_scoping_no_match(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "scoped.yaml"),
        (
            "enabled: true\n"
            "municipalities: ['bonney-lake']\n"
            "must_not:\n"
            "  - {term: {src_ip: '10.0.0.1'}}\n"
        ),
    )
    result = load_filters(str(tmp_path), municipality="puyallup")
    assert result["filter_count"] == 0
    assert result["must_not"] == []


def test_no_municipality_field_always_included(tmp_path: str) -> None:
    """Filters without a municipalities field apply to every municipality."""
    _write(
        os.path.join(str(tmp_path), "global.yaml"),
        "enabled: true\nmust_not:\n  - {term: {src_ip: '5.5.5.5'}}\n",
    )
    result = load_filters(str(tmp_path), municipality="bonney-lake")
    assert result["filter_count"] == 1


# ---------------------------------------------------------------------------
# Malformed YAML
# ---------------------------------------------------------------------------


def test_malformed_yaml_logged_as_error(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "bad.yaml"),
        "enabled: true\nmust_not: [\n",  # unclosed bracket
    )
    result = load_filters(str(tmp_path))
    assert any("YAML parse error" in e or "parse error" in e for e in result["errors"])


def test_missing_must_not_key_logged(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "no_must_not.yaml"),
        "enabled: true\n",
    )
    result = load_filters(str(tmp_path))
    assert any("must_not" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Multi-file merge
# ---------------------------------------------------------------------------


def test_multi_file_merge(tmp_path: str) -> None:
    _write(
        os.path.join(str(tmp_path), "a.yaml"),
        "enabled: true\nmust_not:\n  - {term: {src_ip: '1.1.1.1'}}\n",
    )
    _write(
        os.path.join(str(tmp_path), "b.yaml"),
        "enabled: true\nmust_not:\n  - {term: {src_ip: '2.2.2.2'}}\n",
    )
    result = load_filters(str(tmp_path))
    assert result["filter_count"] == 2
    assert len(result["must_not"]) == 2
    ips = {c["term"]["src_ip"] for c in result["must_not"]}
    assert ips == {"1.1.1.1", "2.2.2.2"}


def test_subdirectory_walk(tmp_path: str) -> None:
    """load_filters() recurses into subdirectories."""
    sub = os.path.join(str(tmp_path), "ips")
    _write(
        os.path.join(sub, "scanners.yaml"),
        "enabled: true\nmust_not:\n  - {term: {src_ip: '3.3.3.3'}}\n",
    )
    result = load_filters(str(tmp_path))
    assert result["filter_count"] == 1
    assert result["must_not"][0]["term"]["src_ip"] == "3.3.3.3"
