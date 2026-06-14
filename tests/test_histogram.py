"""Tests for the histogram core helper and CLI renderer (pure/offline functions only)."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.histogram import query_histogram
from src.querier.histogram_cli import _render, _time_axis

# ---------------------------------------------------------------------------
# _render — pure function, no I/O
# ---------------------------------------------------------------------------

_SAMPLE_BUCKETS = [
    {"key": i * 3_600_000, "key_as_string": f"2026-04-19T{i:02d}:00:00.000Z", "doc_count": c}
    for i, c in enumerate([0, 10, 50, 100, 80, 20, 5, 0])
]


def test_render_returns_correct_length() -> None:
    result = _render(_SAMPLE_BUCKETS, width=len(_SAMPLE_BUCKETS))
    assert len(result) == len(_SAMPLE_BUCKETS)


def test_render_empty_buckets() -> None:
    assert _render([], width=80) == "(no data)"


def test_render_all_zero_counts() -> None:
    buckets = [{"key": 0, "key_as_string": "2026-04-19T00:00:00.000Z", "doc_count": 0}]
    result = _render(buckets, width=10)
    # All-zero: max is treated as 1, round(0/1*8)=0 → first block char (space)
    assert result == " "


def test_render_single_spike() -> None:
    buckets = [
        {"key": 0, "key_as_string": "2026-04-19T00:00:00.000Z", "doc_count": 0},
        {"key": 3_600_000, "key_as_string": "2026-04-19T01:00:00.000Z", "doc_count": 100},
        {"key": 7_200_000, "key_as_string": "2026-04-19T02:00:00.000Z", "doc_count": 0},
    ]
    result = _render(buckets, width=3)
    # Middle bucket is max → full block
    assert result[1] == "█"


def test_render_compresses_when_wider_than_width() -> None:
    # 20 buckets into width=10 → result length == 10
    many = [{"key": i * 3_600_000, "key_as_string": f"T{i}", "doc_count": i * 5} for i in range(20)]
    result = _render(many, width=10)
    assert len(result) == 10


# ---------------------------------------------------------------------------
# _time_axis
# ---------------------------------------------------------------------------


def test_time_axis_length_matches_width() -> None:
    result = _time_axis(_SAMPLE_BUCKETS, bar_width=80)
    assert len(result) == 80


def test_time_axis_empty_buckets() -> None:
    assert _time_axis([], bar_width=80) == ""


# ---------------------------------------------------------------------------
# query_histogram — mock OpenSearch to test query construction
# ---------------------------------------------------------------------------


def _fake_raw(buckets: list[dict]) -> dict:
    return {"aggregations": {"over_time": {"buckets": buckets}}}


def test_query_histogram_passes_log_type_datasets() -> None:
    fake_buckets = [{"key": 0, "key_as_string": "2026-04-19T00:00:00.000Z", "doc_count": 42}]
    with (
        patch("src.querier.histogram.load_with_remap", return_value=([], 0, [])),
        patch(
            "src.querier.histogram.query_opensearch", return_value=_fake_raw(fake_buckets)
        ) as mock_qos,
    ):
        result = query_histogram("conn", interval="1h", time_range="now-24h")

    assert result == [{"key": 0, "key_as_string": "2026-04-19T00:00:00.000Z", "doc_count": 42}]
    body_arg = mock_qos.call_args[0][0]
    assert body_arg["size"] == 0
    assert "over_time" in body_arg["aggs"]
    assert body_arg["aggs"]["over_time"]["date_histogram"]["fixed_interval"] == "1h"


def test_query_histogram_none_when_opensearch_fails() -> None:
    with (
        patch("src.querier.histogram.load_with_remap", return_value=([], 0, [])),
        patch("src.querier.histogram.query_opensearch", return_value=None),
    ):
        result = query_histogram("dns")

    assert result == []


def test_query_histogram_src_ip_list_produces_terms_clause() -> None:
    with (
        patch("src.querier.histogram.load_with_remap", return_value=([], 0, [])),
        patch("src.querier.histogram.query_opensearch", return_value=_fake_raw([])) as mock_qos,
    ):
        query_histogram("conn", src_ip=["1.1.1.1", "2.2.2.2"])

    body_arg = mock_qos.call_args[0][0]
    filter_clauses = body_arg["query"]["bool"]["filter"]
    terms_clause = next(
        (c for c in filter_clauses if "terms" in c and "source.ip" in c["terms"]), None
    )
    assert terms_clause is not None
    assert terms_clause["terms"]["source.ip"] == ["1.1.1.1", "2.2.2.2"]


def test_query_histogram_absolute_timestamps() -> None:
    time_from = "2026-04-19T00:00:00Z"
    time_to = "2026-04-20T00:00:00Z"
    with (
        patch("src.querier.histogram.load_with_remap", return_value=([], 0, [])),
        patch("src.querier.histogram.query_opensearch", return_value=_fake_raw([])) as mock_qos,
    ):
        query_histogram("notice", time_from=time_from, time_to=time_to)

    body_arg = mock_qos.call_args[0][0]
    filter_clauses = body_arg["query"]["bool"]["filter"]
    ts_clause = next(
        (c for c in filter_clauses if "range" in c and "@timestamp" in c["range"]), None
    )
    assert ts_clause is not None
    assert ts_clause["range"]["@timestamp"]["gte"] == time_from
    assert ts_clause["range"]["@timestamp"]["lte"] == time_to
