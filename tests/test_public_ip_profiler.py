"""Tests for public_ip_profiler — query builders, parsers, classifier, orchestrator."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.public_ip_profiler import (
    PublicIPProfile,
    _conn_from_query,
    _conn_to_query,
    _http_to_query,
    _parse_conn_from,
    _parse_conn_to,
    _parse_http_to,
    _parse_rdp_from,
    _parse_reverse_dns,
    _parse_sensor_presence,
    _parse_ssh_from,
    _parse_ssl_to,
    _rdp_from_query,
    _reverse_dns_query,
    _sensor_presence_query,
    _ssh_from_query,
    _ssl_to_query,
    profile_public_ip,
)
from src.profiler.public_role_classifier import classify_public_role

# ---------------------------------------------------------------------------
# Query builder tests — verify correct IP field and dataset filters
# ---------------------------------------------------------------------------


class TestQueryBuilders:
    """Verify query builders produce correct ES query structure."""

    def test_sensor_presence_uses_both_ip_fields(self):
        q = _sensor_presence_query("1.2.3.4", "now-7d")
        should = q["query"]["bool"]["must"][1]["bool"]["should"]
        assert {"term": {"source.ip": "1.2.3.4"}} in should
        assert {"term": {"destination.ip": "1.2.3.4"}} in should

    def test_reverse_dns_filters_on_answers(self):
        q = _reverse_dns_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"zeek.dns.answers": "1.2.3.4"}} in must
        assert {"term": {"event.dataset": "dns"}} in must

    def test_conn_to_uses_dest_ip(self):
        q = _conn_to_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"destination.ip": "1.2.3.4"}} in must
        assert {"term": {"event.dataset": "conn"}} in must

    def test_conn_from_uses_src_ip(self):
        q = _conn_from_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"source.ip": "1.2.3.4"}} in must

    def test_ssl_to_uses_dest_ip(self):
        q = _ssl_to_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"destination.ip": "1.2.3.4"}} in must
        assert {"term": {"event.dataset": "ssl"}} in must

    def test_http_to_uses_dest_ip(self):
        q = _http_to_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"destination.ip": "1.2.3.4"}} in must

    def test_ssh_from_uses_src_ip(self):
        q = _ssh_from_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"source.ip": "1.2.3.4"}} in must
        assert {"term": {"event.dataset": "ssh"}} in must

    def test_rdp_from_uses_src_ip(self):
        q = _rdp_from_query("1.2.3.4", "now-7d")
        must = q["query"]["bool"]["must"]
        assert {"term": {"source.ip": "1.2.3.4"}} in must
        assert {"term": {"event.dataset": "rdp"}} in must


# ---------------------------------------------------------------------------
# Parser tests — extract fields from mock ES aggregation responses
# ---------------------------------------------------------------------------

MOCK_SENSOR_AGGS = {
    "sensors": {
        "buckets": [
            {"key": "hedgehog-east", "doc_count": 1423},
            {"key": "hedgehog-west", "doc_count": 892},
        ]
    },
    "time_range": {
        "min_as_string": "2026-04-24T08:30:00.000Z",
        "max_as_string": "2026-04-30T13:41:00.000Z",
    },
}

MOCK_RDNS_AGGS = {
    "domains": {
        "buckets": [
            {"key": "example.com", "doc_count": 1200},
            {"key": "www.example.com", "doc_count": 892},
        ]
    }
}

MOCK_CONN_TO_AGGS = {
    "dest_ports": {
        "buckets": [
            {
                "key": 443,
                "doc_count": 2100,
                "app_proto": {"buckets": [{"key": "ssl", "doc_count": 2100}]},
            },
            {
                "key": 80,
                "doc_count": 556,
                "app_proto": {"buckets": [{"key": "http", "doc_count": 556}]},
            },
        ]
    },
    "unique_clients": {"value": 45},
    "bytes_to": {"value": 12300000000},
    "bytes_from": {"value": 500000},
    "time_range": {
        "min_as_string": "2026-04-24T08:30:00.000Z",
        "max_as_string": "2026-04-30T13:41:00.000Z",
    },
}

MOCK_CONN_FROM_AGGS = {
    "inbound_ports": {
        "buckets": [
            {"key": 22, "doc_count": 150},
            {"key": 80, "doc_count": 30},
        ]
    },
    "unique_targets": {"value": 15},
}

MOCK_SSL_TO_AGGS = {
    "ja4s": {"buckets": [{"key": "abc123", "doc_count": 2100}]},
    "tls_versions": {"buckets": [{"key": "TLSv1.3", "doc_count": 2000}]},
    "subjects": {"buckets": [{"key": "CN=example.com", "doc_count": 2100}]},
    "issuers": {"buckets": [{"key": "CN=Let's Encrypt", "doc_count": 2100}]},
}

MOCK_HTTP_TO_AGGS = {
    "server_headers": {"buckets": [{"key": "nginx", "doc_count": 500}]},
    "top_uris": {
        "buckets": [
            {"key": "/", "doc_count": 300},
            {"key": "/api/v1", "doc_count": 200},
        ]
    },
}

MOCK_SSH_FROM_AGGS = {
    "server_versions": {
        "buckets": [{"key": "SSH-2.0-OpenSSH_8.9", "doc_count": 50}],
        "sum_other_doc_count": 0,
    }
}

MOCK_RDP_FROM_AGGS = {"cookies": {"buckets": [{"key": "admin", "doc_count": 10}]}}


class TestParsers:
    """Verify parsers extract correct fields from mock aggregations."""

    def test_parse_sensor_presence(self):
        result = _parse_sensor_presence(MOCK_SENSOR_AGGS)
        assert len(result["sensors"]) == 2
        assert result["sensors"][0]["sensor"] == "hedgehog-east"
        assert result["total_records"] == 1423 + 892
        assert result["first_seen"] == "2026-04-24T08:30:00.000Z"

    def test_parse_reverse_dns(self):
        result = _parse_reverse_dns(MOCK_RDNS_AGGS)
        assert len(result["reverse_dns"]) == 2
        assert result["reverse_dns"][0]["domain"] == "example.com"

    def test_parse_conn_to(self):
        result = _parse_conn_to(MOCK_CONN_TO_AGGS)
        assert len(result["services"]) == 2
        assert result["services"][0]["port"] == 443
        assert result["services"][0]["app_proto"] == "ssl"
        assert result["internal_client_count"] == 45
        assert result["bytes_to"] == 12300000000

    def test_parse_conn_from(self):
        result = _parse_conn_from(MOCK_CONN_FROM_AGGS)
        assert len(result["inbound_ports_targeted"]) == 2
        assert result["internal_targets_count"] == 15

    def test_parse_ssl_to(self):
        result = _parse_ssl_to(MOCK_SSL_TO_AGGS)
        assert len(result["ja4s_fingerprints"]) == 1
        assert result["tls_versions"][0]["version"] == "TLSv1.3"
        assert "CN=Let's Encrypt" in result["ssl_issuers"]

    def test_parse_http_to(self):
        result = _parse_http_to(MOCK_HTTP_TO_AGGS)
        assert "nginx" in result["http_server_headers"]
        assert len(result["http_top_uris"]) == 2

    def test_parse_ssh_from(self):
        result = _parse_ssh_from(MOCK_SSH_FROM_AGGS)
        assert result["ssh_inbound"] is True
        assert "SSH-2.0-OpenSSH_8.9" in result["ssh_server_versions"]

    def test_parse_ssh_from_empty(self):
        result = _parse_ssh_from({})
        assert result["ssh_inbound"] is False
        assert result["ssh_server_versions"] == []

    def test_parse_rdp_from(self):
        result = _parse_rdp_from(MOCK_RDP_FROM_AGGS)
        assert result["rdp_inbound"] is True
        assert "admin" in result["rdp_usernames"]

    def test_parse_rdp_from_empty(self):
        result = _parse_rdp_from({})
        assert result["rdp_inbound"] is False


# ---------------------------------------------------------------------------
# Role classifier tests
# ---------------------------------------------------------------------------


def _make_profile(**kwargs) -> PublicIPProfile:
    """Create a PublicIPProfile with overrides."""
    defaults = {"ip": "1.2.3.4", "time_range": "now-7d"}
    defaults.update(kwargs)
    return PublicIPProfile(**defaults)


class TestPublicRoleClassifier:
    """Verify role classification for common scenarios."""

    def test_web_server(self):
        p = _make_profile(
            services=[
                {"port": 443, "app_proto": "ssl", "count": 2100},
                {"port": 80, "app_proto": "http", "count": 556},
            ],
            internal_client_count=20,
            ssl_issuers=["CN=Let's Encrypt Authority X3"],
            reverse_dns=[{"domain": "example.com", "count": 1200}],
        )
        role, conf = classify_public_role(p)
        assert role == "web_server"
        assert conf >= 0.8

    def test_scanner(self):
        p = _make_profile(
            inbound_ports_targeted=[{"port": i, "count": 5} for i in range(22, 35)],
            internal_targets_count=50,
            bytes_to=100,
            bytes_from=100,
        )
        role, conf = classify_public_role(p)
        assert role == "scanner"
        assert conf >= 0.7

    def test_cdn_node(self):
        p = _make_profile(
            org={"name": "Cloudflare", "category": "cdn"},
            services=[{"port": 443, "app_proto": "ssl", "count": 5000}],
            internal_client_count=100,
            reverse_dns=[
                {"domain": "a.example.com", "count": 100},
                {"domain": "b.example.com", "count": 100},
                {"domain": "c.example.com", "count": 100},
            ],
        )
        role, conf = classify_public_role(p)
        assert role == "cdn_node"
        assert conf >= 0.8

    def test_dns_server(self):
        p = _make_profile(
            services=[{"port": 53, "app_proto": "dns", "count": 10000}],
            internal_client_count=200,
        )
        role, conf = classify_public_role(p)
        assert role == "dns_server"
        assert conf >= 0.7

    def test_unknown_empty_profile(self):
        p = _make_profile()
        role, conf = classify_public_role(p)
        assert role == "unknown"
        assert conf == 0.0


# ---------------------------------------------------------------------------
# Orchestrator integration test (mocked ES)
# ---------------------------------------------------------------------------


def _mock_query_opensearch(body, params):
    """Return appropriate mock response based on query content."""
    must = body.get("query", {}).get("bool", {}).get("must", [])
    for clause in must:
        ds = clause.get("term", {}).get("event.dataset")
        if ds == "dns":
            return {"aggregations": MOCK_RDNS_AGGS}
        if ds == "conn":
            # Distinguish conn_to vs conn_from by IP field
            for c in must:
                if c.get("term", {}).get("destination.ip"):
                    return {"aggregations": MOCK_CONN_TO_AGGS}
                if c.get("term", {}).get("source.ip"):
                    return {"aggregations": MOCK_CONN_FROM_AGGS}
        if ds == "ssl":
            return {"aggregations": MOCK_SSL_TO_AGGS}
        if ds == "http":
            return {"aggregations": MOCK_HTTP_TO_AGGS}
        if ds == "ssh":
            return {"aggregations": MOCK_SSH_FROM_AGGS}
        if ds == "rdp":
            return {"aggregations": MOCK_RDP_FROM_AGGS}
    # Default: sensor presence query (no event.dataset filter)
    return {"aggregations": MOCK_SENSOR_AGGS}


class TestProfilePublicIp:
    """Integration test for profile_public_ip with mocked ES."""

    @patch("src.profiler.public_ip_profiler.query_opensearch", side_effect=_mock_query_opensearch)
    @patch("src.profiler.public_ip_profiler.lookup_org", return_value=None)
    def test_full_profile(self, mock_org, mock_es):
        profile = profile_public_ip("1.2.3.4", time_range="now-7d")

        assert profile.ip == "1.2.3.4"
        assert len(profile.sensors) == 2
        assert profile.total_records == 2315
        assert len(profile.reverse_dns) == 2
        assert len(profile.services) == 2
        assert profile.internal_client_count == 45
        assert profile.ssh_inbound is True
        assert profile.rdp_inbound is True
        assert profile.role != "unknown"
        assert profile.confidence > 0

    @patch("src.profiler.public_ip_profiler.query_opensearch", return_value=None)
    @patch("src.profiler.public_ip_profiler.lookup_org", return_value=None)
    def test_empty_profile_no_errors(self, mock_org, mock_es):
        """IP with zero records across all sensors → empty profile, no errors."""
        profile = profile_public_ip("5.6.7.8", time_range="now-7d")

        assert profile.ip == "5.6.7.8"
        assert profile.sensors == []
        assert profile.total_records == 0
        assert profile.services == []
        assert profile.role == "unknown"
        assert profile.confidence == 0.0
