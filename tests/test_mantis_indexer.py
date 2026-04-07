"""Tests for mantis_search IP extraction and role classification."""

from __future__ import annotations

import os
import sys

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

from src.mantis.mantis_search import (
    _classify_ip_roles,
    _extract_ips,
    _extract_private_ips,
    _normalize_issue,
)


# ---------------------------------------------------------------------------
# _extract_ips
# ---------------------------------------------------------------------------


def test_extract_ips_public() -> None:
    assert _extract_ips(["source ip: 1.2.3.4"]) == ["1.2.3.4"]


def test_extract_ips_includes_private() -> None:
    """RFC1918 addresses must be preserved — they may call out to C2 servers."""
    result = _extract_ips(["Source IP: 10.10.1.5"])
    assert "10.10.1.5" in result


def test_extract_ips_excludes_loopback() -> None:
    assert _extract_ips(["127.0.0.1"]) == []


def test_extract_ips_excludes_multicast() -> None:
    assert _extract_ips(["224.0.0.251"]) == []


def test_extract_ips_defanged() -> None:
    assert _extract_ips(["1.2.3[.]4"]) == ["1.2.3.4"]


def test_extract_ips_deduplicates() -> None:
    result = _extract_ips(["1.2.3.4 and 1.2.3.4 again"])
    assert result.count("1.2.3.4") == 1


def test_extract_ips_cidr_extracts_host() -> None:
    """CIDR notation — only the host portion is extracted."""
    result = _extract_ips(["src: 78.153.140.0/24"])
    assert "78.153.140.0" in result


# ---------------------------------------------------------------------------
# _extract_private_ips
# ---------------------------------------------------------------------------


def test_extract_private_ips_returns_rfc1918() -> None:
    result = _extract_private_ips(["10.0.0.1 and 192.168.1.1"])
    assert "10.0.0.1" in result
    assert "192.168.1.1" in result


def test_extract_private_ips_excludes_public() -> None:
    result = _extract_private_ips(["1.2.3.4"])
    assert result == []


# ---------------------------------------------------------------------------
# _classify_ip_roles
# ---------------------------------------------------------------------------


def test_classify_roles_verbose_source_dest() -> None:
    texts = ["Source IP: 1.2.3.4\nDestination IP: 5.6.7.8"]
    src, dest, unknown = _classify_ip_roles(texts, ["1.2.3.4", "5.6.7.8"])
    assert src == ["1.2.3.4"]
    assert dest == ["5.6.7.8"]
    assert unknown == []


def test_classify_roles_abbreviated_src_ip() -> None:
    """src_ip: format (Kibana/Suricata template) must be recognised."""
    texts = ["src_ip: 65.49.1.163\ndest_ip: 10.0.0.5"]
    src, dest, unknown = _classify_ip_roles(texts, ["65.49.1.163", "10.0.0.5"])
    assert src == ["65.49.1.163"]
    assert dest == ["10.0.0.5"]
    assert unknown == []


def test_classify_roles_abbreviated_src_space() -> None:
    """'src IP:' (space separator) must be recognised."""
    texts = ["src IP:  10.0.0.61\ndest IP: 18.65.226.136"]
    src, dest, unknown = _classify_ip_roles(texts, ["10.0.0.61", "18.65.226.136"])
    assert "10.0.0.61" in src
    assert "18.65.226.136" in dest


def test_classify_roles_no_labels_all_unknown() -> None:
    texts = ["Some freeform note mentioning 1.2.3.4 and 5.6.7.8"]
    src, dest, unknown = _classify_ip_roles(texts, ["1.2.3.4", "5.6.7.8"])
    assert src == []
    assert dest == []
    assert set(unknown) == {"1.2.3.4", "5.6.7.8"}


def test_classify_roles_source_only_filters_others() -> None:
    """When source is labelled but dest is not, unlabelled IPs go to unknown."""
    texts = ["Source IP: 1.2.3.4"]
    src, dest, unknown = _classify_ip_roles(texts, ["1.2.3.4", "5.6.7.8"])
    assert src == ["1.2.3.4"]
    assert dest == []
    assert unknown == ["5.6.7.8"]


def test_classify_roles_ip_in_both_treated_as_source() -> None:
    """An IP labelled as both source and dest is classified as source."""
    texts = ["Source IP: 1.2.3.4\nDestination IP: 1.2.3.4"]
    src, dest, unknown = _classify_ip_roles(texts, ["1.2.3.4"])
    assert src == ["1.2.3.4"]
    assert dest == []


def test_classify_roles_private_ip_labelled() -> None:
    """Private IPs can be labelled source or dest (e.g. internal victim host)."""
    texts = ["src_ip: 10.10.1.5\ndest_ip: 203.0.113.1"]
    src, dest, unknown = _classify_ip_roles(texts, ["10.10.1.5", "203.0.113.1"])
    assert "10.10.1.5" in src
    assert "203.0.113.1" in dest


# ---------------------------------------------------------------------------
# _normalize_issue — round-trip schema check
# ---------------------------------------------------------------------------

_SAMPLE_ISSUE = {
    "id": 42,
    "summary": "ET SCAN Zmap",
    "description": (
        "Source IP: 1.2.3.4\n"
        "Source Port: 52807\n"
        "Destination IP: 10.10.3.39\n"
        "Destination Port: 80\n"
    ),
    "steps_to_reproduce": "",
    "additional_information": "",
    "status": {"name": "resolved"},
    "resolution": {"name": "fixed"},
    "severity": {"name": "major"},
    "priority": {"name": "normal"},
    "created_at": "2026-01-01T00:00:00Z",
    "updated_at": "2026-01-02T00:00:00Z",
    "project": {"name": "test-project"},
    "category": {"name": "Security"},
    "reporter": {"id": 1, "name": "student"},
    "handler": {"id": 2, "name": "admin"},
    "notes": [
        {
            "id": 10,
            "reporter": {"id": 2, "name": "admin"},
            "text": "1.2.3.4 has been blocked.",
            "created_at": "2026-01-02T00:00:00Z",
        }
    ],
}


def test_normalize_issue_schema_fields() -> None:
    ticket = _normalize_issue(_SAMPLE_ISSUE, "https://mantis.example.com")
    for field in ("ips", "private_ips", "ip_src", "ip_dest", "ip_unknown"):
        assert field in ticket, f"Missing field: {field}"


def test_normalize_issue_includes_private_ip() -> None:
    ticket = _normalize_issue(_SAMPLE_ISSUE, "https://mantis.example.com")
    assert "10.10.3.39" in ticket["ips"]
    assert "10.10.3.39" in ticket["private_ips"]


def test_normalize_issue_role_classification() -> None:
    ticket = _normalize_issue(_SAMPLE_ISSUE, "https://mantis.example.com")
    assert "1.2.3.4" in ticket["ip_src"]
    assert "10.10.3.39" in ticket["ip_dest"]
    assert ticket["ip_unknown"] == []


def test_normalize_issue_roles_not_derived_from_admin_notes() -> None:
    """Admin note text must not influence role classification."""
    issue = dict(_SAMPLE_ISSUE)
    issue = {
        **_SAMPLE_ISSUE,
        "description": "",  # no structured labels
        "notes": [
            {
                "id": 10,
                "reporter": {"id": 2, "name": "admin"},
                "text": "Source IP: 9.9.9.9 is malicious.",
                "created_at": "2026-01-02T00:00:00Z",
            }
        ],
    }
    ticket = _normalize_issue(issue, "https://mantis.example.com", handler_registry={2})
    # 9.9.9.9 appears only in admin note — must not be classified as source
    assert "9.9.9.9" not in ticket["ip_src"]
    assert "9.9.9.9" in ticket["ip_unknown"]
