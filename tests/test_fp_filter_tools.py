"""Tests for the Tier-5 FP filter read/delete helpers in fp_manager.py."""

from __future__ import annotations

import os
import sys

import pytest
import yaml

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.fp_manager import (
    delete_ip_from_filter,
    load_filter_file,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _write_filter(path: str, clauses: list[dict]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    data = {
        "description": "test filter",
        "author": "pytest",
        "date_added": "2026-01-01",
        "category": "ips",
        "subcategory": "test",
        "enabled": True,
        "must_not": clauses,
    }
    with open(path, "w") as fh:
        yaml.dump(data, fh, default_flow_style=False)


# ---------------------------------------------------------------------------
# delete_ip_from_filter — term clauses
# ---------------------------------------------------------------------------


def test_delete_term_src_ip(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(
        path,
        [
            {"term": {"src_ip": "1.2.3.4"}},
            {"term": {"src_ip": "5.6.7.8"}},
        ],
    )
    removed = delete_ip_from_filter(path, "1.2.3.4")
    assert removed == 1
    remaining = load_filter_file(path)["must_not"]
    assert len(remaining) == 1
    assert remaining[0]["term"]["src_ip"] == "5.6.7.8"


def test_delete_term_dest_ip(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(path, [{"term": {"dest_ip": "10.0.0.1"}}])
    removed = delete_ip_from_filter(path, "10.0.0.1")
    assert removed == 1
    assert load_filter_file(path)["must_not"] == []


def test_delete_leaves_other_clauses_untouched(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(
        path,
        [
            {"term": {"src_ip": "1.2.3.4"}, "comment": "remove this"},
            {"term": {"src_ip": "9.9.9.9"}, "comment": "keep this"},
        ],
    )
    delete_ip_from_filter(path, "1.2.3.4")
    remaining = load_filter_file(path)["must_not"]
    assert len(remaining) == 1
    assert remaining[0]["term"]["src_ip"] == "9.9.9.9"


# ---------------------------------------------------------------------------
# delete_ip_from_filter — terms (multi-value) clauses
# ---------------------------------------------------------------------------


def test_delete_single_ip_from_terms_list(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(path, [{"terms": {"src_ip": ["1.1.1.1", "2.2.2.2", "3.3.3.3"]}}])
    removed = delete_ip_from_filter(path, "2.2.2.2")
    assert removed == 1
    remaining = load_filter_file(path)["must_not"]
    assert len(remaining) == 1
    assert "2.2.2.2" not in remaining[0]["terms"]["src_ip"]
    assert set(remaining[0]["terms"]["src_ip"]) == {"1.1.1.1", "3.3.3.3"}


def test_delete_last_ip_from_terms_drops_clause(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(path, [{"terms": {"src_ip": ["1.1.1.1"]}}])
    removed = delete_ip_from_filter(path, "1.1.1.1")
    assert removed == 1
    assert load_filter_file(path)["must_not"] == []


def test_delete_ip_from_terms_dest_ip(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(path, [{"terms": {"dest_ip": ["10.0.0.1", "10.0.0.2"]}}])
    delete_ip_from_filter(path, "10.0.0.1")
    remaining = load_filter_file(path)["must_not"]
    assert remaining[0]["terms"]["dest_ip"] == ["10.0.0.2"]


# ---------------------------------------------------------------------------
# delete_ip_from_filter — error cases
# ---------------------------------------------------------------------------


def test_delete_raises_file_not_found(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "missing.yaml")
    with pytest.raises(FileNotFoundError):
        delete_ip_from_filter(path, "1.2.3.4")


def test_delete_raises_value_error_when_no_match(tmp_path: str) -> None:
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(path, [{"term": {"src_ip": "9.9.9.9"}}])
    with pytest.raises(ValueError, match="No clauses found"):
        delete_ip_from_filter(path, "1.2.3.4")


def test_delete_removes_multiple_matching_clauses(tmp_path: str) -> None:
    """An IP that appears in two separate clauses — both are removed."""
    path = os.path.join(str(tmp_path), "ips", "test.yaml")
    _write_filter(
        path,
        [
            {"term": {"src_ip": "1.2.3.4"}, "comment": "first"},
            {"term": {"src_ip": "1.2.3.4"}, "comment": "duplicate"},
            {"term": {"src_ip": "5.5.5.5"}},
        ],
    )
    removed = delete_ip_from_filter(path, "1.2.3.4")
    assert removed == 2
    remaining = load_filter_file(path)["must_not"]
    assert len(remaining) == 1
    assert remaining[0]["term"]["src_ip"] == "5.5.5.5"
