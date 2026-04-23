"""Tests for parse_hit() and build_extra_must() on Zeek protocol modules."""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.querier.zeek_modules.capture_loss import CaptureLossModule
from src.querier.zeek_modules.conn import ConnModule
from src.querier.zeek_modules.dhcp import DhcpModule
from src.querier.zeek_modules.dnp3 import Dnp3Module
from src.querier.zeek_modules.dns import DnsModule
from src.querier.zeek_modules.dpd import DpdModule
from src.querier.zeek_modules.files import FilesModule
from src.querier.zeek_modules.ftp import FtpModule
from src.querier.zeek_modules.kerberos import KerberosModule
from src.querier.zeek_modules.modbus import ModbusModule
from src.querier.zeek_modules.ntlm import NtlmModule
from src.querier.zeek_modules.ntp import NtpModule
from src.querier.zeek_modules.pe import PEModule
from src.querier.zeek_modules.radius import RadiusModule
from src.querier.zeek_modules.sip import SipModule
from src.querier.zeek_modules.tunnel import TunnelModule
from src.querier.zeek_modules.x509 import X509Module

# ---------------------------------------------------------------------------
# ConnModule.parse_hit
# ---------------------------------------------------------------------------


class TestConnModuleParseHit:
    MODULE = ConnModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
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
        assert rec["sensor"] == "hedgehog-example"

    def test_zeek_conn_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["duration"] == 1.5
        assert rec["conn_state"] == "SF"

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
        clauses, post_filters = self.MODULE.build_extra_must({})
        assert clauses == []
        assert post_filters == []


# ---------------------------------------------------------------------------
# DnsModule.parse_hit
# ---------------------------------------------------------------------------


class TestDnsModuleParseHit:
    MODULE = DnsModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:05:00Z",
            "host": {"name": "hedgehog-example"},
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
                    "answers": ["198.51.100.34"],
                    "rtt": 0.005,
                }
            },
            "event": {
                "dataset": "dns",
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
        assert rec["answers"] == "198.51.100.34"

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
        clauses, post_filters = self.MODULE.build_extra_must({"dns_query": "evil.com"})
        assert len(clauses) == 1
        assert clauses[0] == {"match_phrase": {"zeek.dns.query": "evil.com"}}
        assert post_filters == []

    def test_build_extra_must_rcode(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"rcode": "NXDOMAIN"})
        assert any("zeek.dns.rcode_name" in c.get("term", {}) for c in clauses)

    def test_build_extra_must_qtype(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"qtype": "MX"})
        assert any("zeek.dns.qtype_name" in c.get("term", {}) for c in clauses)

    def test_build_extra_must_empty_params(self) -> None:
        clauses, post_filters = self.MODULE.build_extra_must({})
        assert clauses == []
        assert post_filters == []

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "example.com" in key
        assert "192.168.1.100" in key


# ---------------------------------------------------------------------------
# FilesModule.parse_hit
# ---------------------------------------------------------------------------


class TestFilesModuleParseHit:
    MODULE = FilesModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "zeek": {
                "files": {
                    "fuid": "FiD1234",
                    "tx_hosts": ["198.51.100.1"],
                    "rx_hosts": ["10.0.0.5"],
                    "source": "HTTP",
                    "mime_type": "application/x-dosexec",
                    "filename": "malware.exe",
                    "total_bytes": 102400,
                    "md5": "a" * 32,
                    "sha1": "b" * 40,
                    "sha256": "c" * 64,
                    "extracted": True,
                    "analyzers": ["MD5", "SHA1", "SHA256"],
                }
            },
            "event": {"dataset": "files"},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "198.51.100.1"
        assert rec["dest_ip"] == "10.0.0.5"
        assert rec["fuid"] == "FiD1234"
        assert rec["mime_type"] == "application/x-dosexec"
        assert rec["filename"] == "malware.exe"

    def test_hashes(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["sha256"] == "c" * 64
        assert rec["md5"] == "a" * 32
        assert rec["sha1"] == "b" * 40

    def test_extracted_flag(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["extracted"] is True

    def test_tx_rx_hosts_empty(self) -> None:
        src = self._src()
        src["zeek"]["files"]["tx_hosts"] = []
        src["zeek"]["files"]["rx_hosts"] = []
        rec = self.MODULE.parse_hit(src)
        assert rec["src_ip"] == ""
        assert rec["dest_ip"] == ""

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["src_ip"] == ""
        assert rec["sha256"] == ""

    def test_dedup_key_with_sha256(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "c" * 64 in key
        assert "198.51.100.1" in key

    def test_dedup_key_no_hash_falls_back_to_md5(self) -> None:
        src = self._src()
        src["zeek"]["files"]["sha256"] = None
        rec = self.MODULE.parse_hit(src)
        key = self.MODULE.dedup_key(rec)
        assert "a" * 32 in key

    def test_dedup_key_no_hashes(self) -> None:
        src = self._src()
        src["zeek"]["files"]["sha256"] = None
        src["zeek"]["files"]["md5"] = None
        rec = self.MODULE.parse_hit(src)
        key = self.MODULE.dedup_key(rec)
        assert "" in key

    def test_build_extra_must_mime(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"mime": "application/x-dosexec"})
        assert len(clauses) == 1
        assert clauses[0] == {"match_phrase": {"zeek.files.mime_type": "application/x-dosexec"}}
        assert pf == []

    def test_build_extra_must_hash_md5(self) -> None:
        h = "a" * 32
        clauses, _ = self.MODULE.build_extra_must({"hash": h})
        assert clauses[0] == {"term": {"zeek.files.md5": h}}

    def test_build_extra_must_hash_sha256(self) -> None:
        h = "c" * 64
        clauses, _ = self.MODULE.build_extra_must({"hash": h})
        assert clauses[0] == {"term": {"zeek.files.sha256": h}}

    def test_build_extra_must_hash_unknown_length_ignored(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"hash": "tooshort"})
        assert clauses == []

    def test_build_extra_must_extracted_only_post_filter(self) -> None:
        _, pf = self.MODULE.build_extra_must({"extracted_only": True})
        assert len(pf) == 1
        assert pf[0]({"extracted": True}) is True
        assert pf[0]({"extracted": False}) is False

    def test_build_extra_must_src_ip_post_filter(self) -> None:
        _, pf = self.MODULE.build_extra_must({"src_ip": "1.2.3.4"})
        assert len(pf) == 1
        assert pf[0]({"src_ip": "1.2.3.4"}) is True
        assert pf[0]({"src_ip": "9.9.9.9"}) is False

    def test_source_ip_not_in_source_fields(self) -> None:
        assert "source.ip" not in self.MODULE.SOURCE_FIELDS


# ---------------------------------------------------------------------------
# X509Module.parse_hit
# ---------------------------------------------------------------------------


class TestX509ModuleParseHit:
    MODULE = X509Module()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "destination": {"port": 443},
            "zeek": {
                "x509": {
                    "certificate": {
                        "subject": "CN=example.com,O=Acme",
                        "issuer": "CN=Let's Encrypt,O=ISRG",
                        "not_valid_before": "2024-01-01T00:00:00Z",
                        "not_valid_after": "2025-01-01T00:00:00Z",
                        "key_alg": "rsaEncryption",
                        "sig_alg": "sha256WithRSAEncryption",
                        "key_length": 2048,
                        "serial": "DEADBEEF",
                    },
                    "basic_constraints": {"ca": False},
                    "san": {"dns": ["example.com", "www.example.com"], "ip": []},
                }
            },
            "network": {"community_id": "1:abc123"},
            "event": {"dataset": "x509", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_certificate_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["subject"] == "CN=example.com,O=Acme"
        assert rec["issuer"] == "CN=Let's Encrypt,O=ISRG"
        assert rec["key_length"] == 2048
        assert rec["serial"] == "DEADBEEF"

    def test_san_dns_list_joined(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert "example.com" in rec["san_dns"]
        assert "www.example.com" in rec["san_dns"]

    def test_san_dns_string_preserved(self) -> None:
        src = self._src()
        src["zeek"]["x509"]["san"]["dns"] = "only.example.com"
        rec = self.MODULE.parse_hit(src)
        assert rec["san_dns"] == "only.example.com"

    def test_community_id_preserved(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["community_id"] == "1:abc123"

    def test_ips_default_to_dash_without_cache(self) -> None:
        # No prepare_hits called — cache should be empty.
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "—"
        assert rec["dest_ip"] == "—"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "CN=example.com,O=Acme" in key

    def test_source_ip_not_in_source_fields(self) -> None:
        assert "source.ip" not in self.MODULE.SOURCE_FIELDS

    def test_build_extra_must_subject(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"subject": "example.com"})
        assert len(clauses) == 1
        assert clauses[0] == {"match_phrase": {"zeek.x509.certificate.subject": "example.com"}}
        assert pf == []

    def test_build_extra_must_self_signed_post_filter(self) -> None:
        _, pf = self.MODULE.build_extra_must({"self_signed": True})
        assert len(pf) == 1
        assert pf[0]({"subject": "CN=foo", "issuer": "CN=foo"}) is True
        assert pf[0]({"subject": "CN=foo", "issuer": "CN=bar"}) is False

    def test_build_extra_must_expired_post_filter(self) -> None:
        _, pf = self.MODULE.build_extra_must({"expired": True})
        assert len(pf) == 1
        assert pf[0]({"not_after": "2000-01-01T00:00:00Z"}) is True
        assert pf[0]({"not_after": "2099-01-01T00:00:00Z"}) is False
        assert pf[0]({"not_after": ""}) is False


# ---------------------------------------------------------------------------
# DhcpModule.parse_hit
# ---------------------------------------------------------------------------


class TestDhcpModuleParseHit:
    MODULE = DhcpModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "0.0.0.0"},
            "destination": {"ip": "255.255.255.255"},
            "zeek": {
                "dhcp": {
                    "client_addr": "192.168.1.50",
                    "server_addr": "192.168.1.1",
                    "assigned_ip": "192.168.1.50",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "host_name": "DESKTOP-ABC",
                    "client_fqdn": "DESKTOP-ABC.corp.local",
                    "domain": "corp.local",
                    "lease_time": 86400,
                    "msg_types": ["DISCOVER", "OFFER", "REQUEST", "ACK"],
                }
            },
            "event": {"dataset": "dhcp", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["mac"] == "aa:bb:cc:dd:ee:ff"
        assert rec["hostname"] == "DESKTOP-ABC"
        assert rec["assigned_ip"] == "192.168.1.50"

    def test_src_ip_prefers_source_ip(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        # ECS source.ip = "0.0.0.0" should take precedence.
        assert rec["src_ip"] == "0.0.0.0"

    def test_src_ip_falls_back_to_client_addr(self) -> None:
        src = self._src()
        del src["source"]
        rec = self.MODULE.parse_hit(src)
        assert rec["src_ip"] == "192.168.1.50"

    def test_msg_types_joined(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert "DISCOVER" in rec["msg_types"]
        assert "ACK" in rec["msg_types"]

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "aa:bb:cc:dd:ee:ff" in key
        assert "192.168.1.50" in key
        assert "DESKTOP-ABC" in key

    def test_build_extra_must_hostname(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"hostname": "DESKTOP"})
        assert len(clauses) == 1
        assert clauses[0] == {"match_phrase": {"zeek.dhcp.host_name": "DESKTOP"}}
        assert pf == []

    def test_build_extra_must_mac(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"mac": "aa:bb:cc:dd:ee:ff"})
        assert clauses[0] == {"term": {"zeek.dhcp.mac": "aa:bb:cc:dd:ee:ff"}}


# ---------------------------------------------------------------------------
# KerberosModule.parse_hit
# ---------------------------------------------------------------------------


class TestKerberosModuleParseHit:
    MODULE = KerberosModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "192.168.1.10", "port": 51234},
            "destination": {"ip": "10.0.0.1", "port": 88},
            "zeek": {
                "kerberos": {
                    "client": "alice@CORP.LOCAL",
                    "service": "krbtgt/CORP.LOCAL@CORP.LOCAL",
                    "success": True,
                    "error_msg": "",
                    "request_type": "AS",
                    "cipher": "aes256-cts-hmac-sha1-96",
                    "forwardable": True,
                    "renewable": True,
                    "from": "2024-06-01T12:00:00Z",
                    "till": "2024-06-01T22:00:00Z",
                }
            },
            "network": {"community_id": "1:abc", "direction": "outbound"},
            "event": {"dataset": "kerberos", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["client"] == "alice@CORP.LOCAL"
        assert rec["service"] == "krbtgt/CORP.LOCAL@CORP.LOCAL"
        assert rec["request_type"] == "AS"
        assert rec["success"] is True

    def test_cipher_and_forwardable(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["cipher"] == "aes256-cts-hmac-sha1-96"
        assert rec["forwardable"] is True

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "alice@CORP.LOCAL" in key
        assert "AS" in key

    def test_build_extra_must_failed_only(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"failed_only": True})
        assert {"term": {"zeek.kerberos.success": False}} in clauses
        assert pf == []

    def test_build_extra_must_request_type(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"request_type": "TGS"})
        assert {"term": {"zeek.kerberos.request_type": "TGS"}} in clauses

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []


# ---------------------------------------------------------------------------
# NtlmModule.parse_hit
# ---------------------------------------------------------------------------


class TestNtlmModuleParseHit:
    MODULE = NtlmModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "192.168.1.20", "port": 55001},
            "destination": {"ip": "10.0.0.5", "port": 445},
            "zeek": {
                "ntlm": {
                    "username": "bob",
                    "domainname": "CORP",
                    "hostname": "WORKSTATION1",
                    "server_nb_computer_name": "SERVER1",
                    "server_dns_computer_name": "server1.corp.local",
                    "server_tree_name": "corp.local",
                    "success": False,
                    "status": "Account locked out",
                }
            },
            "network": {"community_id": "1:xyz", "direction": "internal"},
            "event": {"dataset": "ntlm", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["username"] == "bob"
        assert rec["domain"] == "CORP"
        assert rec["success"] is False
        assert rec["status"] == "Account locked out"

    def test_server_names(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["server_nb_name"] == "SERVER1"
        assert rec["server_dns_name"] == "server1.corp.local"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "bob" in key
        assert "CORP" in key
        assert False in key

    def test_build_extra_must_failed_only(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"failed_only": True})
        assert {"term": {"zeek.ntlm.success": False}} in clauses
        assert pf == []

    def test_build_extra_must_username(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"username": "bob"})
        assert clauses[0] == {"match_phrase": {"zeek.ntlm.username": "bob"}}

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []


# ---------------------------------------------------------------------------
# FtpModule.parse_hit
# ---------------------------------------------------------------------------


class TestFtpModuleParseHit:
    MODULE = FtpModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "192.168.1.30", "port": 60001},
            "destination": {"ip": "198.51.100.10", "port": 21},
            "zeek": {
                "ftp": {
                    "user": "anonymous",
                    "password": "user@example.com",  # pragma: allowlist secret
                    "command": "RETR",
                    "arg": "/pub/file.zip",
                    "mime_type": "application/zip",
                    "file_size": 1048576,
                    "reply_code": 226,
                    "reply_msg": "Transfer complete",
                    "data_channel": {"passive": True},
                }
            },
            "network": {"community_id": "1:ftp1", "direction": "outbound"},
            "event": {"dataset": "ftp", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["user"] == "anonymous"
        assert rec["command"] == "RETR"
        assert rec["arg"] == "/pub/file.zip"
        assert rec["reply_code"] == 226

    def test_password_captured(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["password"] == "user@example.com"  # pragma: allowlist secret

    def test_passive_flag(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["passive"] is True

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "anonymous" in key
        assert "RETR" in key
        assert "/pub/file.zip" in key

    def test_build_extra_must_command(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"command": "STOR"})
        assert {"term": {"zeek.ftp.command": "STOR"}} in clauses
        assert pf == []

    def test_build_extra_must_anon_only_post_filter(self) -> None:
        _, pf = self.MODULE.build_extra_must({"anon_only": True})
        assert len(pf) == 1
        assert pf[0]({"user": "anonymous"}) is True
        assert pf[0]({"user": "ftp"}) is True
        assert pf[0]({"user": "guest"}) is True
        assert pf[0]({"user": "bob"}) is False

    def test_build_extra_must_user(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"user": "alice"})
        assert clauses[0] == {"match_phrase": {"zeek.ftp.user": "alice"}}

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["user"] == ""
        assert rec["command"] == ""


# ---------------------------------------------------------------------------
# RadiusModule.parse_hit
# ---------------------------------------------------------------------------


class TestRadiusModuleParseHit:
    MODULE = RadiusModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "10.0.0.100", "port": 1812},
            "destination": {"ip": "10.0.0.1", "port": 1812},
            "zeek": {
                "radius": {
                    "username": "alice",
                    "result": "success",
                    "mac": "aa:bb:cc:dd:ee:ff",
                    "framed_addr": "192.168.1.50",
                    "remote_ip": "203.0.113.1",
                    "reply_msg": "Access granted",
                    "ttl": 3600,
                }
            },
            "network": {"community_id": "1:rad1"},
            "event": {"dataset": "radius", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["username"] == "alice"
        assert rec["result"] == "success"
        assert rec["mac"] == "aa:bb:cc:dd:ee:ff"
        assert rec["framed_addr"] == "192.168.1.50"

    def test_ttl_and_reply(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["ttl"] == 3600
        assert rec["reply_msg"] == "Access granted"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "alice" in key
        assert "success" in key

    def test_build_extra_must_failed_only(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"failed_only": True})
        assert {"term": {"zeek.radius.result": "failed"}} in clauses
        assert pf == []

    def test_build_extra_must_username(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"username": "alice"})
        assert clauses[0] == {"match_phrase": {"zeek.radius.username": "alice"}}

    def test_build_extra_must_mac(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"mac": "aa:bb:cc:dd:ee:ff"})
        assert clauses[0] == {"term": {"zeek.radius.mac": "aa:bb:cc:dd:ee:ff"}}

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["username"] == ""
        assert rec["result"] == ""
        assert rec["mac"] == ""


# ---------------------------------------------------------------------------
# SipModule.parse_hit
# ---------------------------------------------------------------------------


class TestSipModuleParseHit:
    MODULE = SipModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "192.168.1.10", "port": 5060},
            "destination": {"ip": "192.168.1.20", "port": 5060},
            "zeek": {
                "sip": {
                    "method": "INVITE",
                    "uri": "sip:bob@example.com",
                    "request_from": "sip:alice@example.com",
                    "request_to": "sip:bob@example.com",
                    "call_id": "abc123@example.com",
                    "user_agent": "Linphone/4.4.0",
                    "status_code": 200,
                    "status_msg": "OK",
                }
            },
            "network": {"community_id": "1:sip1"},
            "event": {"dataset": "sip", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["method"] == "INVITE"
        assert rec["uri"] == "sip:bob@example.com"
        assert rec["status_code"] == 200
        assert rec["status_msg"] == "OK"

    def test_call_id_and_agent(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["call_id"] == "abc123@example.com"
        assert rec["user_agent"] == "Linphone/4.4.0"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "INVITE" in key
        assert 200 in key

    def test_build_extra_must_method(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"method": "REGISTER"})
        assert {"term": {"zeek.sip.method": "REGISTER"}} in clauses
        assert pf == []

    def test_build_extra_must_status_code(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"status_code": "404"})
        assert {"term": {"zeek.sip.status_code": "404"}} in clauses

    def test_build_extra_must_user_agent(self) -> None:
        clauses, _ = self.MODULE.build_extra_must({"user_agent": "Linphone"})
        assert clauses[0] == {"match_phrase": {"zeek.sip.user_agent": "Linphone"}}

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["method"] == ""
        assert rec["uri"] == ""
        assert rec["status_code"] is None


# ---------------------------------------------------------------------------
# TunnelModule.parse_hit
# ---------------------------------------------------------------------------


class TestTunnelModuleParseHit:
    MODULE = TunnelModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "10.0.0.5"},
            "destination": {"ip": "203.0.113.10"},
            "zeek": {
                "tunnel": {
                    "tunnel_type": "Tunnel::GRE",
                    "action": "DISCOVERED",
                }
            },
            "network": {"community_id": "1:tun1"},
            "event": {"dataset": "tunnel", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["tunnel_type"] == "Tunnel::GRE"
        assert rec["action"] == "DISCOVERED"

    def test_ip_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "10.0.0.5"
        assert rec["dest_ip"] == "203.0.113.10"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "Tunnel::GRE" in key
        assert "DISCOVERED" in key

    def test_build_extra_must_tunnel_type(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"tunnel_type": "Tunnel::IP"})
        assert {"term": {"zeek.tunnel.tunnel_type": "Tunnel::IP"}} in clauses
        assert pf == []

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["tunnel_type"] == ""
        assert rec["action"] == ""


# ---------------------------------------------------------------------------
# NtpModule.parse_hit
# ---------------------------------------------------------------------------


class TestNtpModuleParseHit:
    MODULE = NtpModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "10.0.0.5", "port": 55000},
            "destination": {"ip": "203.0.113.1", "port": 123},
            "zeek": {
                "ntp": {
                    "version": 4,
                    "mode": 3,
                    "stratum": 2,
                    "poll": 6,
                    "ref_id": "GPS",
                }
            },
            "network": {"community_id": "1:ntp1"},
            "event": {"dataset": "ntp", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["version"] == 4
        assert rec["mode"] == 3
        assert rec["stratum"] == 2
        assert rec["poll"] == 6
        assert rec["ref_id"] == "GPS"

    def test_ip_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "10.0.0.5"
        assert rec["src_port"] == 55000
        assert rec["dest_ip"] == "203.0.113.1"
        assert rec["dest_port"] == 123

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "10.0.0.5" in key
        assert 3 in key

    def test_build_extra_must_mode(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"mode": 3})
        assert {"term": {"zeek.ntp.mode": 3}} in clauses
        assert pf == []

    def test_build_extra_must_mode_string(self) -> None:
        # _ask() returns strings; int() cast should handle this
        clauses, pf = self.MODULE.build_extra_must({"mode": "4"})
        assert {"term": {"zeek.ntp.mode": 4}} in clauses

    def test_build_extra_must_version(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"version": "4"})
        assert {"term": {"zeek.ntp.version": 4}} in clauses

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["version"] is None
        assert rec["mode"] is None
        assert rec["stratum"] is None


# ---------------------------------------------------------------------------
# ModbusModule.parse_hit
# ---------------------------------------------------------------------------


class TestModbusModuleParseHit:
    MODULE = ModbusModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "ot-sensor-01"},
            "source": {"ip": "192.168.1.100", "port": 54321},
            "destination": {"ip": "192.168.1.10", "port": 502},
            "zeek": {
                "modbus": {
                    "function": "Read Coils",
                    "exception": "",
                    "track_address": 42,
                }
            },
            "network": {"community_id": "1:modbus1"},
            "event": {"dataset": "modbus", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["function"] == "Read Coils"
        assert rec["exception"] == ""
        assert rec["track_address"] == 42

    def test_ip_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "192.168.1.100"
        assert rec["dest_ip"] == "192.168.1.10"
        assert rec["dest_port"] == 502

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "Read Coils" in key
        assert "192.168.1.100" in key

    def test_build_extra_must_function(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"function": "Write Single Register"})
        assert {"match_phrase": {"zeek.modbus.function": "Write Single Register"}} in clauses
        assert pf == []

    def test_build_extra_must_exceptions_only(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"exceptions_only": True})
        assert clauses == []
        assert len(pf) == 1
        # Post-filter should accept records with non-empty exception
        assert pf[0]({"exception": "Illegal Function"}) is True
        assert pf[0]({"exception": ""}) is False
        assert pf[0]({}) is False

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["function"] == ""
        assert rec["exception"] == ""
        assert rec["track_address"] is None


# ---------------------------------------------------------------------------
# Dnp3Module.parse_hit
# ---------------------------------------------------------------------------


class TestDnp3ModuleParseHit:
    MODULE = Dnp3Module()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "ot-sensor-01"},
            "source": {"ip": "10.0.1.5", "port": 60000},
            "destination": {"ip": "10.0.1.1", "port": 20000},
            "zeek": {
                "dnp3": {
                    "function_request": "READ",
                    "function_reply": "RESPONSE",
                    "iin": "0x0000",
                }
            },
            "network": {"community_id": "1:dnp1"},
            "event": {"dataset": "dnp3", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["function_request"] == "READ"
        assert rec["function_reply"] == "RESPONSE"
        assert rec["iin"] == "0x0000"

    def test_ip_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "10.0.1.5"
        assert rec["dest_ip"] == "10.0.1.1"
        assert rec["dest_port"] == 20000

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "READ" in key
        assert "10.0.1.5" in key

    def test_build_extra_must_function(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"function": "WRITE"})
        assert {"match_phrase": {"zeek.dnp3.function_request": "WRITE"}} in clauses
        assert pf == []

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["function_request"] == ""
        assert rec["function_reply"] == ""
        assert rec["iin"] == ""


# ---------------------------------------------------------------------------
# PEModule.parse_hit
# ---------------------------------------------------------------------------


class TestPEModuleParseHit:
    MODULE = PEModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "zeek": {
                "pe": {
                    "client": "FcXjAm2wbsGBSqhv7d",
                    "compile_ts": "2023-01-15T08:00:00Z",
                    "os": "Windows",
                    "subsystem": "WINDOWS_GUI",
                    "is_exe": True,
                    "is_64bit": True,
                    "uses_aslr": True,
                    "uses_dep": True,
                    "uses_code_integrity": False,
                    "uses_seh": True,
                    "has_import_table": True,
                    "has_export_table": False,
                    "has_debug_data": False,
                    "section_names": [".text", ".data", ".rsrc"],
                }
            },
            "event": {"dataset": "pe", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["fuid"] == "FcXjAm2wbsGBSqhv7d"
        assert rec["os"] == "Windows"
        assert rec["subsystem"] == "WINDOWS_GUI"
        assert rec["is_exe"] is True
        assert rec["is_64bit"] is True
        assert rec["uses_aslr"] is True
        assert rec["uses_dep"] is True

    def test_section_names_list(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["section_names"] == [".text", ".data", ".rsrc"]

    def test_section_names_string(self) -> None:
        """String section_names should be wrapped in a list."""
        src = self._src()
        src["zeek"]["pe"]["section_names"] = ".text"
        rec = self.MODULE.parse_hit(src)
        assert rec["section_names"] == [".text"]

    def test_file_hash_from_cache(self) -> None:
        """file_hash is populated from thread-local fuid cache set by prepare_hits."""
        import threading

        import src.querier.zeek_modules.pe as pe_mod

        tl = threading.local()
        tl.fuid_hash_cache = {"FcXjAm2wbsGBSqhv7d": "abc123sha256"}
        original = pe_mod._tl
        pe_mod._tl = tl
        try:
            rec = self.MODULE.parse_hit(self._src())
            assert rec["file_hash"] == "abc123sha256"
        finally:
            pe_mod._tl = original

    def test_file_hash_none_on_cache_miss(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["file_hash"] is None

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "Windows" in key
        assert "WINDOWS_GUI" in key
        assert True in key  # is_exe, is_64bit

    def test_build_extra_must_no_aslr(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"no_aslr": True})
        assert clauses == []
        assert len(pf) == 1
        assert pf[0]({"uses_aslr": False}) is True
        assert pf[0]({"uses_aslr": True}) is False
        assert pf[0]({}) is False

    def test_build_extra_must_no_dep(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"no_dep": True})
        assert clauses == []
        assert len(pf) == 1
        assert pf[0]({"uses_dep": False}) is True
        assert pf[0]({"uses_dep": True}) is False

    def test_build_extra_must_32bit_only(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"only_32bit": True})
        assert clauses == []
        assert len(pf) == 1
        assert pf[0]({"is_64bit": False}) is True
        assert pf[0]({"is_64bit": True}) is False

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["fuid"] == ""
        assert rec["os"] == ""
        assert rec["section_names"] == []
        assert rec["file_hash"] is None

    def test_supports_flags(self) -> None:
        assert self.MODULE.SUPPORTS_IP_FILTER is False
        assert self.MODULE.SUPPORTS_ENRICHMENT is True
        assert self.MODULE.SUPPORTS_FP is True
        assert self.MODULE.WEB_CATEGORY == "files"


# ---------------------------------------------------------------------------
# CaptureLossModule.parse_hit
# ---------------------------------------------------------------------------


class TestCaptureLossModuleParseHit:
    MODULE = CaptureLossModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "zeek": {
                "capture_loss": {
                    "ts_delta": 300.0,
                    "peer": "bro",
                    "gaps": 42,
                    "acks": 10000,
                    "percent_lost": 8.5,
                }
            },
            "event": {"dataset": "capture_loss"},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["peer"] == "bro"
        assert rec["gaps"] == 42
        assert rec["acks"] == 10000
        assert rec["percent_lost"] == 8.5
        assert rec["ts_delta"] == 300.0

    def test_sensor(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["sensor"] == "hedgehog-example"
        assert rec["timestamp"] == "2024-06-01T12:00:00Z"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "hedgehog-example" in key
        assert "bro" in key

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["peer"] == ""
        assert rec["gaps"] is None
        assert rec["acks"] is None
        assert rec["percent_lost"] is None

    def test_supports_flags(self) -> None:
        assert self.MODULE.SUPPORTS_IP_FILTER is False
        assert self.MODULE.SUPPORTS_ENRICHMENT is False
        assert self.MODULE.SUPPORTS_FP is False
        assert self.MODULE.WEB_CATEGORY == "diagnostic"

    def test_no_extra_must_override(self) -> None:
        """CaptureLossModule uses the base class default — returns empty clauses and filters."""
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []


# ---------------------------------------------------------------------------
# DpdModule.parse_hit
# ---------------------------------------------------------------------------


class TestDpdModuleParseHit:
    MODULE = DpdModule()

    def _src(self, **overrides: object) -> dict:
        base: dict = {
            "@timestamp": "2024-06-01T12:00:00Z",
            "host": {"name": "hedgehog-example"},
            "source": {"ip": "198.51.100.1", "port": 54321},
            "destination": {"ip": "203.0.113.5", "port": 443},
            "zeek": {
                "dpd": {
                    "proto": "tcp",
                    "analyzer": "SSL",
                    "failure_reason": "not a TLS client hello",
                }
            },
            "network": {"community_id": "1:dpd123"},
            "event": {"dataset": "dpd", "risk_score": None, "risk_score_norm": None},
        }
        base.update(overrides)
        return base

    def test_basic_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["proto"] == "tcp"
        assert rec["analyzer"] == "SSL"
        assert rec["failure_reason"] == "not a TLS client hello"

    def test_ip_fields(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["src_ip"] == "198.51.100.1"
        assert rec["dest_ip"] == "203.0.113.5"
        assert rec["dest_port"] == 443
        assert rec["src_port"] == 54321

    def test_community_id(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        assert rec["community_id"] == "1:dpd123"

    def test_dedup_key(self) -> None:
        rec = self.MODULE.parse_hit(self._src())
        key = self.MODULE.dedup_key(rec)
        assert "198.51.100.1" in key
        assert "203.0.113.5" in key
        assert 443 in key
        assert "SSL" in key

    def test_build_extra_must_analyzer(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({"analyzer": "HTTP"})
        assert {"term": {"zeek.dpd.analyzer": "HTTP"}} in clauses
        assert pf == []

    def test_build_extra_must_empty(self) -> None:
        clauses, pf = self.MODULE.build_extra_must({})
        assert clauses == []
        assert pf == []

    def test_missing_zeek_block(self) -> None:
        rec = self.MODULE.parse_hit({})
        assert rec["proto"] == ""
        assert rec["analyzer"] == ""
        assert rec["failure_reason"] == ""

    def test_web_category(self) -> None:
        assert self.MODULE.WEB_CATEGORY == "diagnostic"
