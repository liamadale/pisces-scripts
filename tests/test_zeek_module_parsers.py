"""Tests for parse_hit() and build_extra_must() on Zeek protocol modules."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.zeek_modules.conn import ConnModule
from src.querier.zeek_modules.dns import DnsModule

# ---------------------------------------------------------------------------
# ConnModule.parse_hit
# ---------------------------------------------------------------------------


class TestConnModuleParseHit:
    MODULE = ConnModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-bonney-lake"},
            "source": {"ip": "198.51.100.1", "port": 54321, "bytes": 1024},
            "destination": {"ip": "203.0.113.5", "port": 443, "bytes": 512},
            "network": {
                "transport": "tcp",
                "protocol": "ssl",
                "community_id": "abc123",
                "direction": "outbound",
            },
            "zeek": {"conn": {"duration": 1.5, "conn_state": "SF"}},
            "event": {
                "dataset": "conn",
                "risk_score": 75.0,
                "risk_score_norm": 80,
            },
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "198.51.100.1"
        assert rec["dest_ip"] == "203.0.113.5"
        assert rec["dest_port"] == 443
        assert rec["src_port"] == 54321
        assert rec["proto"] == "tcp"
        assert rec["app_proto"] == "ssl"

    def test_timestamp_and_sensor(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["timestamp"] == "2024-06-01T12:00:00Z"
        assert rec["sensor"] == "hedgehog-bonney-lake"

    def test_zeek_conn_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["duration"] == 1.5
        assert rec["conn_state"] == "SF"

    def test_risk_score(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["risk_score_norm"] == 80
        assert rec["risk_score"] == 75.0

    def test_bytes(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["bytes_orig"] == 1024
        assert rec["bytes_resp"] == 512

    def test_raw_source_preserved(self) -> None:
        src = self._src()
        rec = self.MODULE.parse_hit(src)
        assert rec["_raw"] is src

    def test_missing_nested_fields_default_empty(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["src_ip"] == ""
        assert rec["dest_ip"] == ""
        assert rec["timestamp"] == ""

    def test_transport_as_list(self) -> None:
        """_first() should unwrap a single-element list."""
        src = self._src()
        src["network"]["transport"] = ["tcp"]
        rec = self.MODULE.parse_hit(src)
        assert rec["proto"] == "tcp"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert key == ("198.51.100.1", "203.0.113.5", 443, "tcp")

    def test_build_extra_must_returns_empty(self) -> None:
        assert self.MODULE.build_extra_must({}) == []


# ---------------------------------------------------------------------------
# DnsModule.parse_hit
# ---------------------------------------------------------------------------


class TestDnsModuleParseHit:
    MODULE = DnsModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:05:00Z",
            "host": {"name": "hedgehog-puyallup"},
            "source": {"ip": "192.168.1.100", "port": 53421},
            "destination": {"ip": "8.8.8.8", "port": 53},
            "network": {
                "transport": "udp",
                "community_id": "def456",
                "direction": "outbound",
            },
            "zeek": {
                "dns": {
                    "query": "example.com",
                    "qtype_name": "A",
                    "rcode_name": "NOERROR",
                    "answers": ["93.184.216.34"],
                    "rtt": 0.005,
                }
            },
            "event": {
                "dataset": "dns",
                "risk_score": None,
                "risk_score_norm": None,
            },
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "192.168.1.100"
        assert rec["dest_ip"] == "8.8.8.8"
        assert rec["dest_port"] == 53

    def test_dns_query_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["query"] == "example.com"
        assert rec["qtype"] == "A"
        assert rec["rcode"] == "NOERROR"

    def test_answers_list_joined(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["answers"] == "93.184.216.34"

    def test_answers_multiple_joined(self) -> None:
        src = self._src()
        src["zeek"]["dns"]["answers"] = ["1.2.3.4", "5.6.7.8"]
        rec = self.MODULE.parse_hit(src)
        assert "1.2.3.4" in rec["answers"]
        assert "5.6.7.8" in rec["answers"]

    def test_answers_empty_list(self) -> None:
        src = self._src()
        src["zeek"]["dns"]["answers"] = []
        rec = self.MODULE.parse_hit(src)
        assert rec["answers"] == ""

    def test_rtt(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["rtt"] == 0.005

    def test_missing_dns_block(self) -> None:
        src = self._src()
        del src["zeek"]
        rec = self.MODULE.parse_hit(src)
        assert rec["query"] == ""
        assert rec["answers"] == ""

    def test_build_extra_must_dns_query(self) -> None:
        clauses = self.MODULE.build_extra_must({"dns_query": "evil.com"})
        assert len(clauses) == 1
        assert clauses[0] == {"match_phrase": {"zeek.dns.query": "evil.com"}}

    def test_build_extra_must_rcode(self) -> None:
        clauses = self.MODULE.build_extra_must({"rcode": "NXDOMAIN"})
        assert any("zeek.dns.rcode_name" in c.get("term", {}) for c in clauses)

    def test_build_extra_must_qtype(self) -> None:
        clauses = self.MODULE.build_extra_must({"qtype": "MX"})
        assert any("zeek.dns.qtype_name" in c.get("term", {}) for c in clauses)

    def test_build_extra_must_empty_params(self) -> None:
        assert self.MODULE.build_extra_must({}) == []

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "example.com" in key
        assert "192.168.1.100" in key
