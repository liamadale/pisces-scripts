"""Tests for SuricataAlertModule — parse_hit, dedup_key, build_extra_must, fp_signature."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.zeek_modules.suricata_alert import SuricataAlertModule


class TestSuricataAlertParseHit:
    MODULE = SuricataAlertModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-sensor01"},
            "source": {"ip": "192.168.1.100", "port": 54097},
            "destination": {
                "ip": "8.8.8.8",
                "port": 53,
                "geo": {"country_name": "United States"},
                "as": {"full": "AS15169 Google LLC"},
            },
            "rule": {
                "name": "ET INFO Observed DNS Query to .biz TLD",
                "id": 2027863,
                "category": "Potentially Bad Traffic",
            },
            "suricata": {
                "alert": {"severity": 2, "action": "allowed"},
            },
            "network": {
                "transport": "udp",
                "application": "dns",
                "community_id": "1:abc123",
                "direction": "outbound",
            },
            "event": {
                "module": "suricata",
                "dataset": "alert",
            },
            "tags": ["CISA_KEV", "cross_segment"],
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "192.168.1.100"
        assert rec["dest_ip"] == "8.8.8.8"
        assert rec["dest_port"] == 53
        assert rec["src_port"] == 54097
        assert rec["sensor"] == "hedgehog-sensor01"
        assert rec["timestamp"] == "2024-06-01T12:00:00Z"

    def test_rule_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["rule_name"] == "ET INFO Observed DNS Query to .biz TLD"
        assert rec["sid"] == 2027863
        assert rec["rule_category"] == "Potentially Bad Traffic"

    def test_alert_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["severity"] == 2
        assert rec["action"] == "allowed"

    def test_network_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["transport"] == "udp"
        assert rec["app_proto"] == "dns"
        assert rec["community_id"] == "1:abc123"
        assert rec["direction"] == "outbound"

    def test_enrichment_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["geo_country"] == "United States"
        assert rec["dest_asn"] == "AS15169 Google LLC"
        assert "CISA_KEV" in rec["tags"]

    def test_missing_fields_default_gracefully(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["src_ip"] == ""
        assert rec["sid"] is None
        assert rec["severity"] is None
        assert rec["tags"] == []


class TestSuricataAlertDedupKey:
    MODULE = SuricataAlertModule()

    def test_dedup_key(self) -> None:
        rec = {"src_ip": "10.0.0.1", "dest_ip": "8.8.8.8", "sid": 2027863}
        assert self.MODULE.dedup_key(rec) == ("10.0.0.1", "8.8.8.8", 2027863)

    def test_dedup_key_missing_fields(self) -> None:
        rec = {}
        assert self.MODULE.dedup_key(rec) == ("", "", "")


class TestSuricataAlertBuildExtraMust:
    MODULE = SuricataAlertModule()

    def test_always_includes_module_clause(self) -> None:
        must, post = self.MODULE.build_extra_must({})
        assert {"term": {"event.module": "suricata"}} in must
        assert post == []

    def test_severity_filter(self) -> None:
        must, _ = self.MODULE.build_extra_must({"severity": 1})
        assert {"term": {"suricata.alert.severity": 1}} in must

    def test_severity_string_coercion(self) -> None:
        must, _ = self.MODULE.build_extra_must({"severity": "2"})
        assert {"term": {"suricata.alert.severity": 2}} in must

    def test_sid_filter(self) -> None:
        must, _ = self.MODULE.build_extra_must({"sid": 2027863})
        assert {"term": {"rule.id": 2027863}} in must

    def test_rule_name_wildcard(self) -> None:
        must, _ = self.MODULE.build_extra_must({"rule_name": "ET INFO"})
        assert {"wildcard": {"rule.name": "*ET INFO*"}} in must

    def test_rule_category_filter(self) -> None:
        must, _ = self.MODULE.build_extra_must({"rule_category": "Potentially Bad Traffic"})
        assert {"term": {"rule.category": "Potentially Bad Traffic"}} in must

    def test_tag_filter(self) -> None:
        must, _ = self.MODULE.build_extra_must({"tag": "CISA_KEV"})
        assert {"term": {"tags": "CISA_KEV"}} in must

    def test_exclude_stream_bool(self) -> None:
        must, _ = self.MODULE.build_extra_must({"exclude_stream": True})
        stream_clause = {
            "bool": {
                "must_not": [
                    {"wildcard": {"rule.name": "SURICATA STREAM*"}},
                    {"wildcard": {"rule.name": "SURICATA QUIC*"}},
                ]
            }
        }
        assert stream_clause in must

    def test_exclude_stream_string(self) -> None:
        must, _ = self.MODULE.build_extra_must({"exclude_stream": "true"})
        # Should still produce the must_not clause
        assert len(must) == 2  # module clause + exclude_stream

    def test_exclude_stream_false_no_clause(self) -> None:
        must, _ = self.MODULE.build_extra_must({"exclude_stream": False})
        assert len(must) == 1  # only the module clause


class TestSuricataAlertFpSignature:
    MODULE = SuricataAlertModule()

    def test_returns_rule_name(self) -> None:
        rec = {"rule_name": "ET INFO Test Rule", "sid": 123}
        assert self.MODULE.fp_signature(rec) == "ET INFO Test Rule"

    def test_falls_back_to_sid(self) -> None:
        rec = {"rule_name": "", "sid": 123}
        assert self.MODULE.fp_signature(rec) == "SID:123"

    def test_no_rule_name_no_sid(self) -> None:
        rec = {"rule_name": "", "sid": None}
        assert self.MODULE.fp_signature(rec) == "SID:None"
