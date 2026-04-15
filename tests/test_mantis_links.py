"""Tests for mantis_search helper functions.

Covers: _extract_ips, _extract_private_ips, _classify_ip_roles,
        _extract_links, sensor_to_project.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mantis.mantis_search import (
    _classify_ip_roles,
    _extract_ips,
    _extract_links,
    _extract_private_ips,
    sensor_to_project,
)

# ---------------------------------------------------------------------------
# _extract_ips
# ---------------------------------------------------------------------------


def test_extract_ips_basic() -> None:
    ips = _extract_ips(["Source was 198.51.100.1 and dest was 203.0.113.5"])
    assert "198.51.100.1" in ips
    assert "203.0.113.5" in ips


def test_extract_ips_defanged_bracket_notation() -> None:
    ips = _extract_ips(["attacker at 198.51.100[.]1"])
    assert "198.51.100.1" in ips


def test_extract_ips_deduplicates() -> None:
    ips = _extract_ips(["1.2.3.4 and 1.2.3.4 again"])
    assert ips.count("1.2.3.4") == 1


def test_extract_ips_excludes_loopback() -> None:
    ips = _extract_ips(["loopback is 127.0.0.1"])
    assert "127.0.0.1" not in ips


def test_extract_ips_excludes_multicast() -> None:
    ips = _extract_ips(["multicast 224.0.0.1 is noise"])
    assert "224.0.0.1" not in ips


def test_extract_ips_includes_rfc1918() -> None:
    """Private addresses are included — internal hosts can be interesting."""
    ips = _extract_ips(["internal host 192.168.1.100"])
    assert "192.168.1.100" in ips


def test_extract_ips_multiple_texts() -> None:
    ips = _extract_ips(["first text 1.1.1.1", "second text 2.2.2.2"])
    assert "1.1.1.1" in ips
    assert "2.2.2.2" in ips


# ---------------------------------------------------------------------------
# _extract_private_ips
# ---------------------------------------------------------------------------


def test_extract_private_ips_only_rfc1918() -> None:
    private = _extract_private_ips(["public 8.8.8.8 and private 10.0.0.1"])
    assert "10.0.0.1" in private
    assert "8.8.8.8" not in private


# ---------------------------------------------------------------------------
# _extract_links
# ---------------------------------------------------------------------------


def test_extract_links_dashboard_opensearch() -> None:
    text = "See https://opensearch.internal/app/discover#/  for details"
    dashboard, ti = _extract_links(text)
    assert any("opensearch" in url.lower() for url in dashboard)
    assert ti == []


def test_extract_links_dashboard_kibana_url() -> None:
    text = "Check https://kibana.example.com/app/alerts"
    dashboard, ti = _extract_links(text)
    assert len(dashboard) == 1
    assert ti == []


def test_extract_links_ti_greynoise() -> None:
    text = "See https://www.greynoise.io/viz/ip/1.2.3.4"
    dashboard, ti = _extract_links(text)
    assert any("greynoise" in url.lower() for url in ti)
    assert dashboard == []


def test_extract_links_ti_abuseipdb() -> None:
    text = "Check https://www.abuseipdb.com/check/1.2.3.4"
    dashboard, ti = _extract_links(text)
    assert any("abuseipdb" in url.lower() for url in ti)


def test_extract_links_mixed() -> None:
    text = (
        "Dashboard: https://opensearch.example.com/app/discover "
        "TI: https://www.shodan.io/host/1.2.3.4"
    )
    dashboard, ti = _extract_links(text)
    assert len(dashboard) == 1
    assert len(ti) == 1


def test_extract_links_no_urls() -> None:
    dashboard, ti = _extract_links("no links here")
    assert dashboard == []
    assert ti == []


def test_extract_links_none_safe() -> None:
    dashboard, ti = _extract_links(None)  # type: ignore[arg-type]
    assert dashboard == []
    assert ti == []


# ---------------------------------------------------------------------------
# _classify_ip_roles
# ---------------------------------------------------------------------------


def test_classify_source_ip() -> None:
    texts = ["Source IP: 198.51.100.1 triggered alert"]
    all_ips = ["198.51.100.1", "203.0.113.5"]
    src, dest, unknown = _classify_ip_roles(texts, all_ips)
    assert "198.51.100.1" in src
    assert "203.0.113.5" in unknown


def test_classify_destination_ip() -> None:
    texts = ["Destination IP: 203.0.113.5 was scanned"]
    all_ips = ["198.51.100.1", "203.0.113.5"]
    src, dest, unknown = _classify_ip_roles(texts, all_ips)
    assert "203.0.113.5" in dest
    assert "198.51.100.1" in unknown


def test_classify_both_roles() -> None:
    texts = ["Source IP: 198.51.100.1 Destination IP: 203.0.113.5"]
    all_ips = ["198.51.100.1", "203.0.113.5"]
    src, dest, unknown = _classify_ip_roles(texts, all_ips)
    assert "198.51.100.1" in src
    assert "203.0.113.5" in dest
    assert unknown == []


def test_classify_source_wins_conflict() -> None:
    """IP appearing as both src and dest is classified as source."""
    texts = ["Source IP: 1.2.3.4 Destination IP: 1.2.3.4"]
    all_ips = ["1.2.3.4"]
    src, dest, unknown = _classify_ip_roles(texts, all_ips)
    assert "1.2.3.4" in src
    assert "1.2.3.4" not in dest


def test_classify_all_unknown_no_labels() -> None:
    texts = ["Something happened involving 198.51.100.1"]
    all_ips = ["198.51.100.1"]
    src, dest, unknown = _classify_ip_roles(texts, all_ips)
    assert src == []
    assert dest == []
    assert "198.51.100.1" in unknown


# ---------------------------------------------------------------------------
# sensor_to_project
# ---------------------------------------------------------------------------


def test_sensor_to_project_strips_prefix() -> None:
    assert sensor_to_project("hedgehog-bonney-lake") == "bonney-lake"


def test_sensor_to_project_no_prefix() -> None:
    assert sensor_to_project("puyallup") == "puyallup"


def test_sensor_to_project_all_returns_none() -> None:
    assert sensor_to_project("all") is None


def test_sensor_to_project_empty_returns_none() -> None:
    assert sensor_to_project("") is None


def test_sensor_to_project_multi_sensor_returns_none() -> None:
    assert sensor_to_project("hedgehog-a,hedgehog-b") is None


def test_sensor_to_project_case_insensitive_all() -> None:
    assert sensor_to_project("ALL") is None
