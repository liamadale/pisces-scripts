"""Tests for pure functions in src/querier/zeek_modules/base.py."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.zeek_modules.base import (
    _remap_clause,
    build_base_query,
    deduplicate_zeek,
    is_private,
)
from src.querier.zeek_modules.notice import NoticeModule
from src.querier.zeek_modules.weird import WeirdModule

# ---------------------------------------------------------------------------
# is_private
# ---------------------------------------------------------------------------


def test_is_private_rfc1918_10() -> None:
    assert is_private("10.1.2.3") is True


def test_is_private_rfc1918_172() -> None:
    assert is_private("172.16.0.1") is True


def test_is_private_rfc1918_192() -> None:
    assert is_private("192.168.1.1") is True


def test_is_private_loopback() -> None:
    assert is_private("127.0.0.1") is True


def test_is_private_link_local() -> None:
    assert is_private("169.254.1.1") is True


def test_is_private_public_ip() -> None:
    assert is_private("8.8.8.8") is False


def test_is_private_invalid_string() -> None:
    assert is_private("not-an-ip") is False


# ---------------------------------------------------------------------------
# _remap_clause
# ---------------------------------------------------------------------------


def test_remap_term_src_ip() -> None:
    clause = {"term": {"src_ip": "1.2.3.4"}}
    result = _remap_clause(clause)
    assert result == {"term": {"source.ip": "1.2.3.4"}}


def test_remap_term_dest_ip() -> None:
    clause = {"term": {"dest_ip": "5.6.7.8"}}
    result = _remap_clause(clause)
    assert result == {"term": {"destination.ip": "5.6.7.8"}}


def test_remap_terms_clause() -> None:
    clause = {"terms": {"src_ip": ["1.1.1.1", "2.2.2.2"]}}
    result = _remap_clause(clause)
    assert "source.ip" in result["terms"]
    assert "src_ip" not in result["terms"]


def test_remap_unknown_field_passthrough() -> None:
    clause = {"term": {"zeek.dns.query": "example.com"}}
    result = _remap_clause(clause)
    assert result == {"term": {"zeek.dns.query": "example.com"}}


def test_remap_bool_recurses() -> None:
    clause = {
        "bool": {
            "must_not": [
                {"term": {"src_ip": "10.0.0.1"}},
            ]
        }
    }
    result = _remap_clause(clause)
    inner = result["bool"]["must_not"][0]
    assert inner == {"term": {"source.ip": "10.0.0.1"}}


def test_remap_non_dict_passthrough() -> None:
    assert _remap_clause("string") == "string"  # type: ignore[arg-type]


def test_remap_preserves_original() -> None:
    """_remap_clause must not mutate the input."""
    original = {"term": {"src_ip": "1.2.3.4"}}
    _remap_clause(original)
    assert original == {"term": {"src_ip": "1.2.3.4"}}


# ---------------------------------------------------------------------------
# build_base_query
# ---------------------------------------------------------------------------


def test_build_base_query_timestamp_must() -> None:
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.ip"],
        limit=100,
        time_range="now-24h",
        sensors=None,
        datasets=["conn"],
    )
    must = body["query"]["bool"]["filter"]
    assert any("range" in c and "@timestamp" in c["range"] for c in must)


def test_build_base_query_dataset_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["dns"],
    )
    must = body["query"]["bool"]["filter"]
    dataset_clause = next((c for c in must if "terms" in c and "event.dataset" in c["terms"]), None)
    assert dataset_clause is not None
    assert dataset_clause["terms"]["event.dataset"] == ["dns"]


def test_build_base_query_all_datasets_omits_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["all"],
    )
    must = body["query"]["bool"]["filter"]
    assert not any("terms" in c and "event.dataset" in c.get("terms", {}) for c in must)


def test_build_base_query_sensor_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=["hedgehog-example"],
        datasets=["conn"],
    )
    must = body["query"]["bool"]["filter"]
    sensor_clause = next((c for c in must if "terms" in c and "host.name" in c["terms"]), None)
    assert sensor_clause is not None
    assert "hedgehog-example" in sensor_clause["terms"]["host.name"]


def test_build_base_query_src_ip_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        src_ip_filter="198.51.100.1",
    )
    must = body["query"]["bool"]["filter"]
    ip_clause = next((c for c in must if "term" in c and "source.ip" in c["term"]), None)
    assert ip_clause is not None
    assert ip_clause["term"]["source.ip"] == "198.51.100.1"


def test_build_base_query_dest_ip_filter() -> None:
    """dest_ip_filter must appear in the ES filter clauses, not as a post-filter."""
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.ip", "destination.ip"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        dest_ip_filter="8.8.8.8",
    )
    must = body["query"]["bool"]["filter"]
    ip_clause = next((c for c in must if "term" in c and "destination.ip" in c["term"]), None)
    assert ip_clause is not None, "dest_ip_filter must be pushed into the ES filter clause"
    assert ip_clause["term"]["destination.ip"] == "8.8.8.8"


def test_build_base_query_src_and_dest_ip_filter() -> None:
    """src and dest IP filters must both appear in the ES filter clauses simultaneously."""
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.ip", "destination.ip"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        src_ip_filter="1.2.3.4",
        dest_ip_filter="8.8.8.8",
    )
    must = body["query"]["bool"]["filter"]
    src_clause = next((c for c in must if "term" in c and "source.ip" in c["term"]), None)
    dest_clause = next((c for c in must if "term" in c and "destination.ip" in c["term"]), None)
    assert src_clause is not None and src_clause["term"]["source.ip"] == "1.2.3.4"
    assert dest_clause is not None and dest_clause["term"]["destination.ip"] == "8.8.8.8"


def test_build_base_query_public_only_adds_must_not() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        public_only=True,
    )
    must_not = body["query"]["bool"]["must_not"]
    assert len(must_not) > 0


def test_build_base_query_size_and_sort() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.ip", "destination.ip"],
        limit=42,
        time_range="now-6h",
        sensors=None,
        datasets=["conn"],
    )
    assert body["size"] == 42
    assert body["sort"] == [{"@timestamp": {"order": "desc"}}]
    assert "_source" in body


def test_build_base_query_params_structure() -> None:
    _, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
    )
    assert params["method"] == "POST"
    assert "arkime_sessions3" in params["path"]


# ---------------------------------------------------------------------------
# deduplicate_zeek
# ---------------------------------------------------------------------------


def _rec(src_ip: str, dest_ip: str, port: int, ts: str, sensor: str = "s1") -> dict:
    return {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": port,
        "proto": "tcp",
        "timestamp": ts,
        "sensor": sensor,
    }


def _key(rec: dict) -> tuple:
    return (rec["src_ip"], rec["dest_ip"], rec["dest_port"], rec["proto"])


def test_dedup_single_record() -> None:
    records = [_rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z")]
    result = deduplicate_zeek(records, _key)
    assert len(result) == 1
    assert result[0]["freq"] == 1


def test_dedup_groups_identical_flows() -> None:
    records = [
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:01:00Z"),
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z"),
    ]
    result = deduplicate_zeek(records, _key)
    assert len(result) == 1
    assert result[0]["freq"] == 2


def test_dedup_keeps_most_recent() -> None:
    records = [
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:01:00Z"),
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z"),
    ]
    result = deduplicate_zeek(records, _key)
    assert result[0]["timestamp"] == "2024-01-01T00:01:00Z"


def test_dedup_distinct_flows_separate() -> None:
    records = [
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z"),
        _rec("9.9.9.9", "5.6.7.8", 80, "2024-01-01T00:00:00Z"),
    ]
    result = deduplicate_zeek(records, _key)
    assert len(result) == 2


def test_dedup_sorted_by_descending_frequency() -> None:
    records = [
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z"),
        _rec("9.9.9.9", "5.6.7.8", 80, "2024-01-01T00:00:00Z"),
        _rec("9.9.9.9", "5.6.7.8", 80, "2024-01-01T00:01:00Z"),
        _rec("9.9.9.9", "5.6.7.8", 80, "2024-01-01T00:02:00Z"),
    ]
    result = deduplicate_zeek(records, _key)
    assert result[0]["src_ip"] == "9.9.9.9"
    assert result[0]["freq"] == 3


def test_dedup_collects_sensors() -> None:
    records = [
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:00:00Z", sensor="s1"),
        _rec("1.2.3.4", "5.6.7.8", 443, "2024-01-01T00:01:00Z", sensor="s2"),
    ]
    result = deduplicate_zeek(records, _key)
    assert set(result[0]["sensors"]) == {"s1", "s2"}


def test_dedup_empty_list() -> None:
    assert deduplicate_zeek([], _key) == []


# ---------------------------------------------------------------------------
# §4.3 Port / proto filters in build_base_query
# ---------------------------------------------------------------------------


def test_build_base_query_dest_port_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["destination.port"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        dest_port_filter=443,
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "term" in c and "destination.port" in c["term"]), None)
    assert clause is not None
    assert clause["term"]["destination.port"] == 443


def test_build_base_query_src_port_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.port"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        src_port_filter=12345,
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "term" in c and "source.port" in c["term"]), None)
    assert clause is not None
    assert clause["term"]["source.port"] == 12345


def test_build_base_query_proto_filter() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        proto_filter="udp",
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "term" in c and "network.transport" in c["term"]), None)
    assert clause is not None
    assert clause["term"]["network.transport"] == "udp"


def test_build_base_query_dest_port_list() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["destination.port"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        dest_port_filter=[80, 443, 8080],
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "terms" in c and "destination.port" in c["terms"]), None)
    assert clause is not None
    assert clause["terms"]["destination.port"] == [80, 443, 8080]


# ---------------------------------------------------------------------------
# §4.4 Multi-value src_ip / dest_ip in build_base_query
# ---------------------------------------------------------------------------


def test_build_base_query_src_ip_list() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["source.ip"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        src_ip_filter=["1.1.1.1", "2.2.2.2"],
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "terms" in c and "source.ip" in c["terms"]), None)
    assert clause is not None
    assert clause["terms"]["source.ip"] == ["1.1.1.1", "2.2.2.2"]


def test_build_base_query_dest_ip_list() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=["destination.ip"],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        dest_ip_filter=["8.8.8.8", "1.1.1.1"],
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "terms" in c and "destination.ip" in c["terms"]), None)
    assert clause is not None
    assert clause["terms"]["destination.ip"] == ["8.8.8.8", "1.1.1.1"]


def test_build_base_query_proto_list() -> None:
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-1h",
        sensors=None,
        datasets=["conn"],
        proto_filter=["tcp", "udp"],
    )
    must = body["query"]["bool"]["filter"]
    clause = next((c for c in must if "terms" in c and "network.transport" in c["terms"]), None)
    assert clause is not None
    assert clause["terms"]["network.transport"] == ["tcp", "udp"]


# ---------------------------------------------------------------------------
# §4.6 Absolute timestamp override in build_base_query
# ---------------------------------------------------------------------------


def test_build_base_query_absolute_timestamps() -> None:
    time_from = "2026-04-19T00:00:00Z"
    time_to = "2026-04-20T00:00:00Z"
    body, _ = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=10,
        time_range="now-24h",
        sensors=None,
        datasets=["conn"],
        time_from=time_from,
        time_to=time_to,
    )
    must = body["query"]["bool"]["filter"]
    ts_clause = next((c for c in must if "range" in c and "@timestamp" in c["range"]), None)
    assert ts_clause is not None
    assert ts_clause["range"]["@timestamp"]["gte"] == time_from
    assert ts_clause["range"]["@timestamp"]["lte"] == time_to


# ---------------------------------------------------------------------------
# NoticeModule.build_extra_must — wildcard / exact match
# ---------------------------------------------------------------------------

_notice = NoticeModule()
_weird = WeirdModule()


def test_notice_exact_match_uses_term() -> None:
    clauses, _ = _notice.build_extra_must({"notice_note": "Scan::Port_Scan"})
    assert len(clauses) == 1
    assert "term" in clauses[0]
    assert clauses[0]["term"]["zeek.notice.note.keyword"] == "Scan::Port_Scan"


def test_notice_trailing_wildcard_uses_wildcard_query() -> None:
    clauses, _ = _notice.build_extra_must({"notice_note": "Scan::*"})
    assert len(clauses) == 1
    assert "wildcard" in clauses[0]
    assert clauses[0]["wildcard"]["zeek.notice.note.keyword"] == "Scan::*"


def test_notice_question_mark_uses_wildcard_query() -> None:
    clauses, _ = _notice.build_extra_must({"notice_note": "SSH::Brute_Force_?"})
    assert "wildcard" in clauses[0]


def test_notice_no_filter_returns_empty() -> None:
    clauses, _ = _notice.build_extra_must({})
    assert clauses == []


def test_weird_exact_match_uses_term() -> None:
    clauses, _ = _weird.build_extra_must({"weird_name": "bad_HTTP_reply"})
    assert len(clauses) == 1
    assert "term" in clauses[0]
    assert clauses[0]["term"]["rule.name.keyword"] == "bad_HTTP_reply"


def test_weird_trailing_wildcard_uses_wildcard_query() -> None:
    clauses, _ = _weird.build_extra_must({"weird_name": "bad_*"})
    assert len(clauses) == 1
    assert "wildcard" in clauses[0]
    assert clauses[0]["wildcard"]["rule.name.keyword"] == "bad_*"


def test_weird_no_filter_returns_empty() -> None:
    clauses, _ = _weird.build_extra_must({})
    assert clauses == []
