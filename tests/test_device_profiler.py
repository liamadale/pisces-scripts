"""Tests for device_profiler — Phase 1a: conn aggregation round-trip."""

from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.profiler.device_profiler import (
    DeviceProfile,
    _extract_share_names,
    _parse_dns,
    _parse_http,
    _parse_inbound,
    _parse_outbound,
    _parse_rdp,
    _parse_smb_inbound,
    _parse_smb_outbound,
    _parse_ssh,
    _parse_ssl,
    extract_hostname_from_unc,
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
        """Verify all 9 queries are sent with correct sensor and time range."""
        mock_qs.return_value = {"aggregations": {}}
        profile_device("10.0.0.50", time_range="now-3d", sensor="hedgehog-test")
        assert mock_qs.call_count == 11
        calls = mock_qs.call_args_list
        bodies = [c[0][0] for c in calls]

        # Verify sensor and time range in all queries
        for body in bodies:
            must = body["query"]["bool"]["must"]
            sensors = [
                c["term"]["host.name"] for c in must if "term" in c and "host.name" in c["term"]
            ]
            assert sensors == ["hedgehog-test"]
            time_ranges = [c["range"]["@timestamp"]["gte"] for c in must if "range" in c]
            assert time_ranges == ["now-3d"]
            time_ranges = [c["range"]["@timestamp"]["gte"] for c in must if "range" in c]
            assert time_ranges == ["now-3d"]


# ---------------------------------------------------------------------------
# Hostname extraction tests
# ---------------------------------------------------------------------------


class TestExtractHostnameFromUnc:
    def test_fqdn_path(self) -> None:
        hostname, domain = extract_hostname_from_unc(["\\\\SERVER1.corp.example.com\\IPC$"])
        assert hostname == "SERVER1"
        assert domain == "corp.example.com"

    def test_short_name(self) -> None:
        hostname, domain = extract_hostname_from_unc(["\\\\FILESVR\\Data"])
        assert hostname == "FILESVR"
        assert domain is None

    def test_most_common_wins(self) -> None:
        paths = [
            "\\\\DC1.corp.example.com\\IPC$",
            "\\\\DC1.corp.example.com\\SYSVOL",
            "\\\\DC1.corp.example.com\\NETLOGON",
            "\\\\OTHER.corp.example.com\\IPC$",
        ]
        hostname, domain = extract_hostname_from_unc(paths)
        assert hostname == "DC1"
        assert domain == "corp.example.com"

    def test_empty_list(self) -> None:
        hostname, domain = extract_hostname_from_unc([])
        assert hostname is None
        assert domain is None

    def test_case_normalized(self) -> None:
        hostname, _ = extract_hostname_from_unc(["\\\\server1.example.com\\share"])
        assert hostname == "SERVER1"


class TestExtractShareNames:
    def test_basic(self) -> None:
        shares = _extract_share_names(["\\\\SRV\\IPC$", "\\\\SRV\\Data"])
        assert shares == ["Data", "IPC$"]

    def test_empty(self) -> None:
        assert _extract_share_names([]) == []

    def test_no_share_part(self) -> None:
        assert _extract_share_names(["\\\\SRV"]) == []


# ---------------------------------------------------------------------------
# _parse_dns tests
# ---------------------------------------------------------------------------


class TestParseDns:
    def test_basic(self) -> None:
        aggs = {
            "top_domains": {
                "buckets": [
                    {"key": "example.com", "doc_count": 50},
                    {"key": "test.local", "doc_count": 10},
                ]
            },
            "qtypes": {"buckets": [{"key": "A", "doc_count": 55}]},
            "resolvers": {"buckets": [{"key": "10.0.0.1", "doc_count": 60}]},
        }
        result = _parse_dns(aggs)
        assert len(result["dns_top_domains"]) == 2
        assert result["dns_top_domains"][0]["domain"] == "example.com"
        assert result["dns_qtypes"][0]["qtype"] == "A"
        assert result["dns_resolvers"] == ["10.0.0.1"]

    def test_empty(self) -> None:
        result = _parse_dns({})
        assert result["dns_top_domains"] == []
        assert result["dns_resolvers"] == []


# ---------------------------------------------------------------------------
# _parse_ssl tests
# ---------------------------------------------------------------------------


class TestParseSsl:
    def test_basic(self) -> None:
        aggs = {
            "ja4_hashes": {"buckets": [{"key": "t13d1516h2_abc", "doc_count": 300}]},
            "sni_values": {"buckets": [{"key": "www.example.com", "doc_count": 200}]},
            "tls_versions": {"buckets": [{"key": "TLSv1.3", "doc_count": 300}]},
        }
        result = _parse_ssl(aggs)
        assert result["ja4_fingerprints"][0]["hash"] == "t13d1516h2_abc"
        assert result["ssl_sni_values"] == ["www.example.com"]
        assert result["tls_versions"][0]["version"] == "TLSv1.3"

    def test_empty(self) -> None:
        result = _parse_ssl({})
        assert result["ja4_fingerprints"] == []
        assert result["ssl_sni_values"] == []


# ---------------------------------------------------------------------------
# _parse_http tests
# ---------------------------------------------------------------------------


class TestParseHttp:
    def test_basic(self) -> None:
        aggs = {
            "user_agents": {"buckets": [{"key": "Mozilla/5.0", "doc_count": 100}]},
            "ua_os_names": {"buckets": [{"key": "Windows 10", "doc_count": 100}]},
            "top_hosts": {"buckets": [{"key": "api.example.com", "doc_count": 50}]},
            "ja4h_fingerprints": {"buckets": [{"key": "ge11cn020000_abc", "doc_count": 80}]},
            "proxy_connects": {"doc_count": 3},
        }
        result = _parse_http(aggs)
        assert result["user_agents"] == ["Mozilla/5.0"]
        assert result["user_agent_os"] == ["Windows 10"]
        assert result["http_top_hosts"][0]["host"] == "api.example.com"
        assert result["ja4h_fingerprints"][0]["hash"] == "ge11cn020000_abc"
        assert result["http_proxy_count"] == 3

    def test_empty(self) -> None:
        result = _parse_http({})
        assert result["user_agents"] == []
        assert result["http_proxy_count"] == 0


# ---------------------------------------------------------------------------
# _parse_smb tests
# ---------------------------------------------------------------------------


class TestParseSmbOutbound:
    def test_basic(self) -> None:
        aggs = {
            "remote_paths": {
                "buckets": [
                    {"key": "\\\\FILESVR\\Data", "doc_count": 10},
                    {"key": "\\\\FILESVR\\IPC$", "doc_count": 5},
                ]
            }
        }
        result = _parse_smb_outbound(aggs)
        assert "Data" in result["smb_shares_accessed"]
        assert "IPC$" in result["smb_shares_accessed"]

    def test_empty(self) -> None:
        assert _parse_smb_outbound({})["smb_shares_accessed"] == []


class TestParseSmbInbound:
    def test_hostname_extraction(self) -> None:
        aggs = {
            "unc_paths": {
                "buckets": [
                    {"key": "\\\\DC1.corp.example.com\\IPC$", "doc_count": 20},
                    {"key": "\\\\DC1.corp.example.com\\SYSVOL", "doc_count": 10},
                ]
            }
        }
        result = _parse_smb_inbound(aggs)
        assert result["hostname"] == "DC1"
        assert result["ad_domain"] == "corp.example.com"
        assert "IPC$" in result["smb_shares_hosted"]
        assert "SYSVOL" in result["smb_shares_hosted"]

    def test_empty(self) -> None:
        result = _parse_smb_inbound({})
        assert result["hostname"] is None
        assert result["smb_shares_hosted"] == []


# ---------------------------------------------------------------------------
# _parse_rdp tests
# ---------------------------------------------------------------------------


class TestParseRdp:
    def test_inbound_and_outbound(self) -> None:
        aggs = {
            "inbound": {
                "doc_count": 5,
                "cookies": {"buckets": [{"key": "admin", "doc_count": 5}]},
            },
            "outbound": {
                "doc_count": 2,
                "targets": {"buckets": [{"key": "10.0.0.20", "doc_count": 2}]},
            },
        }
        result = _parse_rdp(aggs)
        assert result["rdp_inbound"] is True
        assert result["rdp_usernames"] == ["admin"]
        assert result["admin_targets"] == ["10.0.0.20"]

    def test_no_rdp(self) -> None:
        result = _parse_rdp({})
        assert result["rdp_inbound"] is False
        assert result["rdp_usernames"] == []


# ---------------------------------------------------------------------------
# _parse_ssh tests
# ---------------------------------------------------------------------------


class TestParseSsh:
    def test_inbound_and_outbound(self) -> None:
        aggs = {
            "inbound": {
                "doc_count": 10,
                "hassh_server": {"buckets": [{"key": "abc123", "doc_count": 10}]},
                "server_versions": {"buckets": [{"key": "SSH-2.0-OpenSSH_9.7", "doc_count": 10}]},
            },
            "outbound": {
                "doc_count": 3,
                "targets": {"buckets": [{"key": "10.0.0.30", "doc_count": 3}]},
                "hassh_client": {"buckets": [{"key": "def456", "doc_count": 3}]},
                "client_versions": {"buckets": [{"key": "SSH-2.0-PuTTY", "doc_count": 3}]},
            },
        }
        result = _parse_ssh(aggs)
        assert result["ssh_inbound"] is True
        assert result["hassh_server_fingerprints"][0]["hash"] == "abc123"
        assert result["ssh_server_versions"] == ["SSH-2.0-OpenSSH_9.7"]
        assert result["hassh_fingerprints"][0]["hash"] == "def456"
        assert result["ssh_client_versions"] == ["SSH-2.0-PuTTY"]
        assert result["ssh_admin_targets"] == ["10.0.0.30"]

    def test_no_ssh(self) -> None:
        result = _parse_ssh({})
        assert result["ssh_inbound"] is False
        assert result["hassh_fingerprints"] == []


# ---------------------------------------------------------------------------
# _parse_dhcp tests
# ---------------------------------------------------------------------------


class TestParseDhcp:
    def test_basic(self) -> None:
        from src.profiler.device_profiler import _parse_dhcp

        aggs = {
            "mac": {"buckets": [{"key": "aa:bb:cc:dd:ee:ff", "doc_count": 10}]},
            "hostname": {"buckets": [{"key": "WORKSTATION1", "doc_count": 10}]},
        }
        result = _parse_dhcp(aggs)
        assert result["mac"] == "aa:bb:cc:dd:ee:ff"
        assert result["dhcp_hostname"] == "WORKSTATION1"

    def test_empty(self) -> None:
        from src.profiler.device_profiler import _parse_dhcp

        result = _parse_dhcp({})
        assert result["mac"] is None
        assert result["dhcp_hostname"] is None


# ---------------------------------------------------------------------------
# _parse_kerberos_ntlm tests
# ---------------------------------------------------------------------------


class TestParseKerberosNtlm:
    def test_combined(self) -> None:
        from src.profiler.device_profiler import _parse_kerberos_ntlm

        aggs = {
            "krb_clients": {
                "buckets": [
                    {"key": "admin@CORP.LOCAL", "doc_count": 50},
                    {"key": "svc_backup@CORP.LOCAL", "doc_count": 10},
                ]
            },
            "ntlm_users": {
                "buckets": [
                    {"key": "admin", "doc_count": 30},
                    {"key": "jsmith", "doc_count": 5},
                ]
            },
        }
        result = _parse_kerberos_ntlm(aggs)
        assert "admin@CORP.LOCAL" in result["users"]
        assert "jsmith" in result["users"]
        assert len(result["users"]) == 4

    def test_empty(self) -> None:
        from src.profiler.device_profiler import _parse_kerberos_ntlm

        assert _parse_kerberos_ntlm({})["users"] == []


# ---------------------------------------------------------------------------
# JA4 decoder tests
# ---------------------------------------------------------------------------


class TestDecodeJa4:
    def test_tls13_h2(self) -> None:
        from src.profiler.ja4_decoder import decode_ja4

        result = decode_ja4("t13d1516h2_8daaf6152771_d8a2da3f94cd")
        # May resolve to "Chromium Browser" via JA4DB, or prefix decode
        assert result and result != "t13d1516h2_8daaf6152771_d8a2da3f94cd"

    def test_tls12_h1(self) -> None:
        from src.profiler.ja4_decoder import decode_ja4

        result = decode_ja4("t12d2808h1_d943125447b4_4cccce2e0d64")
        assert "TLS 1.2" in result
        assert "HTTP/1.1" in result

    def test_quic(self) -> None:
        from src.profiler.ja4_decoder import decode_ja4

        result = decode_ja4("q13d1516h2_abc")
        assert "QUIC" in result

    def test_empty(self) -> None:
        from src.profiler.ja4_decoder import decode_ja4

        assert decode_ja4("") == ""
        assert decode_ja4("short") == "short"
