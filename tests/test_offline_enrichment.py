"""Tests for the OfflineEnrichmentProvider and OfflineEnrichment dataclass.

Exercises blocklist lookup, Shodan InternetDB cache, local registry priors,
and paid API cache integration.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

# Allow imports from project root (same pattern as the CLI scripts)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.mantis.ticket_enrichment.offline import (
    OfflineEnrichment,
    OfflineEnrichmentProvider,
    _parse_cidr_txt,
    _parse_feodo_json,
    _parse_ip_txt,
    _parse_threatfox_json,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_provider(tmp_path: str) -> OfflineEnrichmentProvider:
    """Return a provider backed by an isolated temp directory."""
    return OfflineEnrichmentProvider(data_dir=tmp_path)


def _write_json(path: str, data: object) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        json.dump(data, fh)


# ---------------------------------------------------------------------------
# Blocklist parsing unit tests
# ---------------------------------------------------------------------------


def test_parse_cidr_txt_basic() -> None:
    content = "# Spamhaus DROP\n192.0.2.0/24 ; SBL123\n10.0.0.0/8\n"
    nets = _parse_cidr_txt(content)
    assert ipaddress.IPv4Network("192.0.2.0/24") in nets
    assert ipaddress.IPv4Network("10.0.0.0/8") in nets


def test_parse_cidr_txt_skips_invalid() -> None:
    content = "not-a-cidr\n1.2.3.4/24\n"
    nets = _parse_cidr_txt(content)
    assert len(nets) == 1


def test_parse_ip_txt_basic() -> None:
    content = "# ET compromised\n1.2.3.4\n5.6.7.8\n"
    ips = _parse_ip_txt(content)
    assert "1.2.3.4" in ips
    assert "5.6.7.8" in ips


def test_parse_feodo_json_basic() -> None:
    data = [{"ip_address": "198.51.100.1"}, {"ip_address": "203.0.113.5"}]
    ips = _parse_feodo_json(json.dumps(data))
    assert "198.51.100.1" in ips
    assert "203.0.113.5" in ips


def test_parse_threatfox_json_ip_port() -> None:
    data = {
        "data": [
            {"ioc_type": "ip:port", "ioc_value": "198.51.100.10:4444"},
            {"ioc_type": "domain", "ioc_value": "evil.example.com"},
        ]
    }
    ips = _parse_threatfox_json(json.dumps(data))
    assert "198.51.100.10" in ips
    assert len(ips) == 1  # domain entry excluded


# ---------------------------------------------------------------------------
# Blocklist lookup (in-memory)
# ---------------------------------------------------------------------------


def test_blocklist_lookup_cidr_hit(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    # Inject a CIDR for testing
    provider._cidr_prefixes["test_list"] = [ipaddress.IPv4Network("198.51.100.0/24")]
    assert "test_list" in provider._lookup_blocklists("198.51.100.42")


def test_blocklist_lookup_ip_set_hit(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    provider._ip_sets["feodo"] = {"198.51.100.1"}
    assert "feodo" in provider._lookup_blocklists("198.51.100.1")


def test_blocklist_lookup_miss(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    assert provider._lookup_blocklists("203.0.113.99") == []


def test_blocklist_lookup_invalid_ip(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    provider._cidr_prefixes["test"] = [ipaddress.IPv4Network("0.0.0.0/0")]
    # Should not raise; just returns []
    result = provider._lookup_blocklists("not-an-ip")
    assert result == []


# ---------------------------------------------------------------------------
# Shodan InternetDB cache
# ---------------------------------------------------------------------------


def test_shodan_cache_hit(tmp_path: str) -> None:
    """A cached entry within TTL should return without an HTTP call."""
    provider = _make_provider(tmp_path)
    provider._ecache["1.2.3.4"] = {
        "fetched_at": datetime.now(tz=timezone.utc).isoformat(),
        "shodan_internetdb": {"tags": ["scanner"], "vulns": ["CVE-2021-44228"]},
    }

    with patch("requests.get") as mock_get:
        tags, vulns = provider._lookup_shodan_internetdb("1.2.3.4")
        mock_get.assert_not_called()

    assert tags == ["scanner"]
    assert vulns == ["CVE-2021-44228"]


def test_shodan_cache_miss_calls_api(tmp_path: str) -> None:
    """Cold-path should call the InternetDB URL and cache the result."""
    provider = _make_provider(tmp_path)

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.ok = True
    mock_resp.json.return_value = {
        "tags": ["honeypot"],
        "vulns": [],
        "ports": [22, 80],
    }

    _patch = "src.mantis.ticket_enrichment.offline.requests.get"
    # Use a genuinely global IP (Python 3.11+ marks 198.51.100.x as private)
    with patch(_patch, return_value=mock_resp) as mock_get:
        tags, vulns = provider._lookup_shodan_internetdb("45.33.32.156")
        mock_get.assert_called_once()

    assert "honeypot" in tags
    assert "45.33.32.156" in provider._ecache


def test_shodan_404_caches_empty(tmp_path: str) -> None:
    """A 404 from InternetDB should cache an empty entry."""
    provider = _make_provider(tmp_path)

    mock_resp = MagicMock()
    mock_resp.status_code = 404

    _patch = "src.mantis.ticket_enrichment.offline.requests.get"
    with patch(_patch, return_value=mock_resp):
        tags, vulns = provider._lookup_shodan_internetdb("5.9.64.10")

    assert tags == []
    assert "5.9.64.10" in provider._ecache


def test_shodan_stale_cache_refetches(tmp_path: str) -> None:
    """An entry older than 30 days should trigger a re-fetch."""
    provider = _make_provider(tmp_path)
    old_ts = (datetime.now(tz=timezone.utc) - timedelta(days=31)).isoformat()
    provider._ecache["1.2.3.4"] = {
        "fetched_at": old_ts,
        "shodan_internetdb": {"tags": ["old_tag"], "vulns": []},
    }

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.ok = True
    mock_resp.json.return_value = {"tags": ["scanner"], "vulns": []}

    _patch = "src.mantis.ticket_enrichment.offline.requests.get"
    with patch(_patch, return_value=mock_resp) as mock_get:
        tags, _ = provider._lookup_shodan_internetdb("1.2.3.4")
        mock_get.assert_called_once()

    assert "scanner" in tags


# ---------------------------------------------------------------------------
# Local prior lookup
# ---------------------------------------------------------------------------


def test_local_prior_malicious(tmp_path: str) -> None:
    """IP with ≥2 malicious tickets and no FP entry → 'malicious'."""
    provider = _make_provider(tmp_path)
    provider._mal_by_ip["1.2.3.4"] = {"ticket_count": 2, "ticket_ids": ["1", "2"]}
    assert provider._lookup_local_prior("1.2.3.4") == "malicious"


def test_local_prior_malicious_below_threshold(tmp_path: str) -> None:
    """IP with only 1 malicious ticket → no prior (insufficient evidence)."""
    provider = _make_provider(tmp_path)
    provider._mal_by_ip["1.2.3.4"] = {"ticket_count": 1, "ticket_ids": ["1"]}
    assert provider._lookup_local_prior("1.2.3.4") is None


def test_local_prior_fp(tmp_path: str) -> None:
    """IP with ≥3 FP tickets and no malicious entry → 'false_positive'."""
    provider = _make_provider(tmp_path)
    provider._fp_by_ip["8.8.8.8"] = {"ticket_ids": ["10", "11", "12"]}
    assert provider._lookup_local_prior("8.8.8.8") == "false_positive"


def test_local_prior_fp_below_threshold(tmp_path: str) -> None:
    """IP with only 2 FP tickets → no prior."""
    provider = _make_provider(tmp_path)
    provider._fp_by_ip["8.8.8.8"] = {"ticket_ids": ["10", "11"]}
    assert provider._lookup_local_prior("8.8.8.8") is None


def test_local_prior_conflicted(tmp_path: str) -> None:
    """IP in both registries → 'conflicted' (regardless of ticket counts)."""
    provider = _make_provider(tmp_path)
    provider._mal_by_ip["5.5.5.5"] = {"ticket_count": 5, "ticket_ids": ["1"] * 5}
    provider._fp_by_ip["5.5.5.5"] = {"ticket_ids": ["2", "3", "4"]}
    assert provider._lookup_local_prior("5.5.5.5") == "conflicted"


def test_local_prior_none(tmp_path: str) -> None:
    """IP not in either registry → None."""
    provider = _make_provider(tmp_path)
    assert provider._lookup_local_prior("192.0.2.1") is None


# ---------------------------------------------------------------------------
# API cache (paid) round-trip
# ---------------------------------------------------------------------------


def test_save_and_retrieve_api_result(tmp_path: str) -> None:
    """save_api_result() persists and _lookup_api_cache() retrieves it."""
    provider = _make_provider(tmp_path)
    provider.save_api_result(
        "198.51.100.99",
        greynoise={"classification": "malicious"},
        abuseipdb={"score": 87},
    )
    gn, abuse, country = provider._lookup_api_cache("198.51.100.99")
    assert gn == "malicious"
    assert abuse == 87
    assert country is None  # no country in fixture abuseipdb result


def test_has_fresh_api_cache_true(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    provider.save_api_result(
        "1.2.3.4",
        greynoise={"classification": "benign"},
    )
    assert provider.has_fresh_api_cache("1.2.3.4") is True


def test_has_fresh_api_cache_false_missing(tmp_path: str) -> None:
    provider = _make_provider(tmp_path)
    assert provider.has_fresh_api_cache("9.9.9.9") is False


# ---------------------------------------------------------------------------
# enrich_ticket() integration
# ---------------------------------------------------------------------------


def test_enrich_ticket_aggregates_signals(tmp_path: str) -> None:
    """enrich_ticket() unions signals from multiple IPs in a ticket."""
    provider = _make_provider(tmp_path)
    provider._cidr_prefixes["spamhaus_drop"] = [
        ipaddress.IPv4Network("198.51.100.0/24")
    ]
    provider._mal_by_ip["203.0.113.1"] = {
        "ticket_count": 3,
        "ticket_ids": ["1", "2", "3"],
    }

    _patch = "src.mantis.ticket_enrichment.offline.requests.get"
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    ticket = {"ips": ["198.51.100.5", "203.0.113.1"]}
    with patch(_patch, return_value=mock_resp):
        result = provider.enrich_ticket(ticket)

    assert "spamhaus_drop" in result.blocklist_hits
    assert result.local_prior == "malicious"


def test_enrich_ticket_most_severe_prior_wins(tmp_path: str) -> None:
    """When multiple IPs have different priors, most-severe wins."""
    provider = _make_provider(tmp_path)
    # IP1: false_positive
    provider._fp_by_ip["198.51.100.1"] = {"ticket_ids": ["a", "b", "c"]}
    # IP2: both → conflicted (highest severity)
    provider._mal_by_ip["198.51.100.2"] = {
        "ticket_count": 2,
        "ticket_ids": ["x", "y"],
    }
    provider._fp_by_ip["198.51.100.2"] = {"ticket_ids": ["z", "z2", "z3"]}

    _patch = "src.mantis.ticket_enrichment.offline.requests.get"
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    ticket = {"ips": ["198.51.100.1", "198.51.100.2"]}
    with patch(_patch, return_value=mock_resp):
        result = provider.enrich_ticket(ticket)
    assert result.local_prior == "conflicted"


def test_enrich_ticket_most_severe_greynoise_wins(tmp_path: str) -> None:
    """When multiple IPs have different GreyNoise results, malicious wins."""
    provider = _make_provider(tmp_path)
    now = datetime.now(tz=timezone.utc).isoformat()
    provider._ecache["198.51.100.10"] = {
        "fetched_at": now,
        "shodan_internetdb": {"tags": [], "vulns": []},
        "greynoise": {"classification": "benign"},
    }
    provider._ecache["198.51.100.11"] = {
        "fetched_at": now,
        "shodan_internetdb": {"tags": [], "vulns": []},
        "greynoise": {"classification": "malicious"},
    }

    ticket = {"ips": ["198.51.100.10", "198.51.100.11"]}
    result = provider.enrich_ticket(ticket)
    assert result.greynoise_classification == "malicious"


# ---------------------------------------------------------------------------
# Registry loading from disk
# ---------------------------------------------------------------------------


def test_loads_local_registries_from_disk(tmp_path: str) -> None:
    """Provider loads malicious_ips and false_positive_ips on init."""
    mal_data = [{"ip": "10.0.0.1", "ticket_count": 3, "ticket_ids": ["1", "2", "3"]}]
    fp_data = [{"ip": "10.0.0.2", "ticket_ids": ["a", "b", "c"]}]

    _write_json(
        os.path.join(tmp_path, "tickets", "enriched", "malicious_ips.json"),
        mal_data,
    )
    _write_json(
        os.path.join(tmp_path, "tickets", "enriched", "false_positive_ips.json"),
        fp_data,
    )

    provider = _make_provider(tmp_path)
    assert "10.0.0.1" in provider._mal_by_ip
    assert "10.0.0.2" in provider._fp_by_ip


def test_missing_registries_do_not_crash(tmp_path: str) -> None:
    """Provider starts cleanly even when registry files don't exist yet."""
    provider = _make_provider(tmp_path)
    assert provider._mal_by_ip == {}
    assert provider._fp_by_ip == {}


# ---------------------------------------------------------------------------
# OfflineEnrichment dataclass defaults
# ---------------------------------------------------------------------------


def test_offline_enrichment_defaults() -> None:
    oe = OfflineEnrichment()
    assert oe.blocklist_hits == []
    assert oe.shodan_tags == []
    assert oe.shodan_vulns == []
    assert oe.asn_tier is None
    assert oe.local_prior is None
    assert oe.greynoise_classification is None
    assert oe.abuseipdb_confidence is None
