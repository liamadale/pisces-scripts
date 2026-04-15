"""Tests for device_profiler — Phase 1a: conn aggregation round-trip."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.device_profiler import (
    DeviceProfile,
    _parse_inbound,
    _parse_outbound,
    profile_device,
)

# ---------------------------------------------------------------------------
# Mock OpenSearch aggregation responses
# ---------------------------------------------------------------------------

MOCK_OUTBOUND_RESPONSE = {
    "aggregations": {
        "dest_ports": {
            "buckets": [
                {"key": 443, "doc_count": 500},
                {"key": 80, "doc_count": 120},
                {"key": 53, "doc_count": 45},
            ]
        },
        "app_protos": {
            "buckets": [
                {"key": "ssl", "doc_count": 500},
                {"key": "dns", "doc_count": 45},
                {"key": "http", "doc_count": 120},
            ]
        },
        "unique_dests": {"value": 87},
        "total_bytes": {"value": 1048576},
        "ja4t_fingerprints": {
            "buckets": [
                {"key": "65535_2-1-3-1-1-4_1460_8", "doc_count": 600},
                {"key": "64240_2-1-3-1-1-4_1460_8", "doc_count": 30},
            ]
        },
        "time_range": {
            "min_as_string": "2024-06-01T08:00:00.000Z",
            "max_as_string": "2024-06-07T22:00:00.000Z",
        },
    }
}

MOCK_INBOUND_RESPONSE = {
    "aggregations": {
        "inbound_ports": {
            "buckets": [
                {
                    "key": 53,
                    "doc_count": 669,
                    "app_proto": {"buckets": [{"key": "dns", "doc_count": 669}]},
                },
                {
                    "key": 389,
                    "doc_count": 222,
                    "app_proto": {"buckets": [{"key": "ldap", "doc_count": 222}]},
                },
                {
                    "key": 88,
                    "doc_count": 122,
                    "app_proto": {"buckets": [{"key": "krb", "doc_count": 122}]},
                },
                {
                    "key": 445,
                    "doc_count": 83,
                    "app_proto": {"buckets": [{"key": "smb", "doc_count": 83}]},
                },
            ]
        },
        "unique_clients": {"value": 42},
        "total_bytes": {"value": 2097152},
        "time_range": {
            "min_as_string": "2024-06-01T06:00:00.000Z",
            "max_as_string": "2024-06-07T23:59:00.000Z",
        },
    }
}


# ---------------------------------------------------------------------------
# _parse_outbound tests
# ---------------------------------------------------------------------------


class TestParseOutbound:
    def test_dest_ports(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert result["dest_port_distribution"] == {443: 500, 80: 120, 53: 45}

    def test_protocol_mix(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert result["protocol_mix"]["ssl"] == 500
        assert result["protocol_mix"]["dns"] == 45

    def test_unique_dests(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert result["unique_dest_count"] == 87

    def test_bytes_sent(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert result["bytes_sent"] == 1048576

    def test_ja4t_fingerprints(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert len(result["ja4t_fingerprints"]) == 2
        assert result["ja4t_fingerprints"][0]["hash"] == "65535_2-1-3-1-1-4_1460_8"
        assert result["ja4t_fingerprints"][0]["count"] == 600

    def test_timestamps(self) -> None:
        result = _parse_outbound(MOCK_OUTBOUND_RESPONSE["aggregations"])
        assert result["first_seen"] == "2024-06-01T08:00:00.000Z"
        assert result["last_seen"] == "2024-06-07T22:00:00.000Z"

    def test_empty_aggs(self) -> None:
        result = _parse_outbound({})
        assert result["dest_port_distribution"] == {}
        assert result["protocol_mix"] == {}
        assert result["unique_dest_count"] == 0
        assert result["bytes_sent"] == 0
        assert result["ja4t_fingerprints"] == []
        assert result["first_seen"] == ""


# ---------------------------------------------------------------------------
# _parse_inbound tests
# ---------------------------------------------------------------------------


class TestParseInbound:
    def test_inbound_services(self) -> None:
        result = _parse_inbound(MOCK_INBOUND_RESPONSE["aggregations"])
        assert len(result["inbound_services"]) == 4
        svc = result["inbound_services"][0]
        assert svc["port"] == 53
        assert svc["app_proto"] == "dns"
        assert svc["count"] == 669

    def test_inbound_service_no_proto(self) -> None:
        """Port bucket with no app_proto sub-agg buckets."""
        aggs = {
            "inbound_ports": {
                "buckets": [
                    {"key": 9100, "doc_count": 5, "app_proto": {"buckets": []}},
                ]
            },
            "unique_clients": {"value": 1},
            "total_bytes": {"value": 0},
            "time_range": {},
        }
        result = _parse_inbound(aggs)
        assert result["inbound_services"][0]["app_proto"] == ""

    def test_unique_clients(self) -> None:
        result = _parse_inbound(MOCK_INBOUND_RESPONSE["aggregations"])
        assert result["inbound_client_count"] == 42

    def test_bytes_received(self) -> None:
        result = _parse_inbound(MOCK_INBOUND_RESPONSE["aggregations"])
        assert result["bytes_received"] == 2097152

    def test_timestamps(self) -> None:
        result = _parse_inbound(MOCK_INBOUND_RESPONSE["aggregations"])
        assert result["first_seen"] == "2024-06-01T06:00:00.000Z"

    def test_empty_aggs(self) -> None:
        result = _parse_inbound({})
        assert result["inbound_services"] == []
        assert result["inbound_client_count"] == 0
        assert result["bytes_received"] == 0


# ---------------------------------------------------------------------------
# profile_device round-trip tests
# ---------------------------------------------------------------------------


class TestProfileDevice:
    def _mock_query(self, body: dict, params: dict) -> dict:
        """Return mock response based on whether query is outbound or inbound."""
        must = body.get("query", {}).get("bool", {}).get("must", [])
        for clause in must:
            if "term" in clause and "source.ip" in clause["term"]:
                return MOCK_OUTBOUND_RESPONSE
            if "term" in clause and "destination.ip" in clause["term"]:
                return MOCK_INBOUND_RESPONSE
        return {"aggregations": {}}

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_round_trip(self, mock_qs: object) -> None:
        mock_qs.side_effect = self._mock_query
        profile = profile_device("10.0.0.50", time_range="now-7d", sensor="hedgehog-test")
        assert isinstance(profile, DeviceProfile)
        assert profile.ip == "10.0.0.50"
        assert profile.sensor == "hedgehog-test"

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_inbound_services_populated(self, mock_qs: object) -> None:
        mock_qs.side_effect = self._mock_query
        profile = profile_device("10.0.0.50", time_range="now-7d", sensor="hedgehog-test")
        assert len(profile.inbound_services) == 4
        ports = [s["port"] for s in profile.inbound_services]
        assert 53 in ports
        assert 389 in ports

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_outbound_populated(self, mock_qs: object) -> None:
        mock_qs.side_effect = self._mock_query
        profile = profile_device("10.0.0.50", time_range="now-7d", sensor="hedgehog-test")
        assert profile.dest_port_distribution[443] == 500
        assert profile.protocol_mix["ssl"] == 500
        assert profile.unique_dest_count == 87

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_timestamp_merge(self, mock_qs: object) -> None:
        """first_seen takes the earliest, last_seen takes the latest."""
        mock_qs.side_effect = self._mock_query
        profile = profile_device("10.0.0.50", time_range="now-7d", sensor="hedgehog-test")
        # Inbound first_seen (06:00) < outbound first_seen (08:00)
        assert profile.first_seen == "2024-06-01T06:00:00.000Z"
        # Inbound last_seen (23:59) > outbound last_seen (22:00)
        assert profile.last_seen == "2024-06-07T23:59:00.000Z"

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_ja4t_fingerprints(self, mock_qs: object) -> None:
        mock_qs.side_effect = self._mock_query
        profile = profile_device("10.0.0.50", time_range="now-7d", sensor="hedgehog-test")
        assert len(profile.ja4t_fingerprints) == 2
        assert profile.ja4t_fingerprints[0]["hash"] == "65535_2-1-3-1-1-4_1460_8"

    def test_public_ip_raises(self) -> None:
        import pytest

        with pytest.raises(ValueError, match="not a private IP"):
            profile_device("8.8.8.8", time_range="now-7d", sensor="test")

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_null_response_handling(self, mock_qs: object) -> None:
        """query_opensearch returning None should produce empty profile."""
        mock_qs.return_value = None
        profile = profile_device("10.0.0.1", time_range="now-7d", sensor="hedgehog-test")
        assert profile.inbound_services == []
        assert profile.dest_port_distribution == {}
        assert profile.first_seen == ""

    @patch("src.profiler.device_profiler.query_opensearch")
    def test_query_bodies_correct(self, mock_qs: object) -> None:
        """Verify the actual query bodies sent to OpenSearch."""
        mock_qs.return_value = {"aggregations": {}}
        profile_device("10.0.0.50", time_range="now-3d", sensor="hedgehog-test")
        assert mock_qs.call_count == 2
        calls = mock_qs.call_args_list
        bodies = [c[0][0] for c in calls]

        # One query should have source.ip, the other destination.ip
        src_queries = [
            b
            for b in bodies
            if any("source.ip" in c.get("term", {}) for c in b["query"]["bool"]["must"])
        ]
        dst_queries = [
            b
            for b in bodies
            if any("destination.ip" in c.get("term", {}) for c in b["query"]["bool"]["must"])
        ]
        assert len(src_queries) == 1
        assert len(dst_queries) == 1

        # Verify sensor and time range in both
        for body in bodies:
            must = body["query"]["bool"]["must"]
            sensors = [
                c["term"]["host.name"] for c in must if "term" in c and "host.name" in c["term"]
            ]
            assert sensors == ["hedgehog-test"]
            time_ranges = [c["range"]["@timestamp"]["gte"] for c in must if "range" in c]
            assert time_ranges == ["now-3d"]
