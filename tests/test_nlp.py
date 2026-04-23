"""Tests for src/mantis/ticket_enrichment/nlp module."""

from __future__ import annotations

import os
import sys

import pytest

# Allow imports from project root (same pattern as the CLI scripts).
sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

from src.mantis.ticket_enrichment.nlp import (
    extract_entities,
    extract_ip_roles,
    is_available,
    is_negated,
)

# All tests below require spaCy + en_core_web_sm to be installed.
# Skip the whole module if unavailable rather than failing with misleading errors.
pytestmark = pytest.mark.skipif(not is_available(), reason="spaCy + en_core_web_sm not installed")


# ------------------------------------------------------------------
# Availability
# ------------------------------------------------------------------


def test_spacy_available() -> None:
    """Documents whether spaCy is available in this environment."""
    assert isinstance(is_available(), bool)


# ------------------------------------------------------------------
# is_negated
# ------------------------------------------------------------------


class TestIsNegated:
    """Negation detection using spaCy dependency parsing."""

    def test_simple_not(self) -> None:
        assert is_negated("this is not malicious in this case", "malicious")

    def test_not_with_emphasis(self) -> None:
        assert is_negated("the traffic itself is not malicious", "malicious")

    def test_contrastive_clause(self) -> None:
        """Second clause is affirmative — should return False."""
        text = "these are not a threat; however, 198.51.100.86 appears to have malicious history"
        assert is_negated(text, "malicious") is False

    def test_cannot(self) -> None:
        assert is_negated(
            "I cannot find an infection point that would support this",
            "infection",
        )

    def test_negated_compound(self) -> None:
        assert is_negated(
            "not malicious and is expected traffic",
            "malicious",
        )

    def test_semantic_negator_fails(self) -> None:
        assert is_negated("fails to confirm exploitation", "exploitation")

    def test_affirmative(self) -> None:
        assert is_negated("the traffic is malicious", "malicious") is False

    def test_keyword_not_found(self) -> None:
        """Returns None when keyword is absent as a token."""
        result = is_negated("the sky is blue", "malicious")
        assert result is None

    def test_real_admin_note_benign(self) -> None:
        text = (
            "This alert seems to be legitimate traffic from "
            "sonicwall. This alert was triggered because Java 8 "
            "is considered outdated and legacy, but the traffic "
            "itself is not malicious."
        )
        assert is_negated(text, "malicious")

    def test_real_admin_note_mixed(self) -> None:
        text = (
            "203.0.113.242, 203.0.113.243 all appear to be "
            "CISA hygiene scans that are not a threat; however, "
            "198.51.100.86 appears to have malicious history "
            "and the alerts seem to warrant escalation"
        )
        assert is_negated(text, "malicious") is False

    def test_non_prefix_sibling(self) -> None:
        """'non malicious traffic' — non is sibling modifier."""
        assert is_negated(
            "this appears to be non malicious traffic",
            "malicious",
        )

    def test_non_prefix_child(self) -> None:
        """'thankfully non malicious' — non is advmod child."""
        assert is_negated(
            "This is outstanding and, in this case, thankfully non malicious.",
            "malicious",
        )


# ------------------------------------------------------------------
# extract_ip_roles
# ------------------------------------------------------------------


class TestExtractIpRoles:
    """IP source/dest role extraction from freeform text."""

    def test_from_to_pattern(self) -> None:
        roles = extract_ip_roles(
            "Traffic originated from internal host "
            "192.168.10.135 to external IP 203.0.113.1 "
            "over port 443"
        )
        assert roles is not None
        by_ip = {r.ip: r.role for r in roles}
        assert by_ip["192.168.10.135"] == "source"
        assert by_ip["203.0.113.1"] == "dest"

    def test_attacker_scanned(self) -> None:
        roles = extract_ip_roles("An attacker at 10.0.0.1 scanned 192.168.1.1")
        assert roles is not None
        by_ip = {r.ip: r.role for r in roles}
        assert by_ip["10.0.0.1"] == "source"
        assert by_ip["192.168.1.1"] == "dest"

    def test_compound_labels(self) -> None:
        roles = extract_ip_roles("source IP 198.51.100.0 sent traffic to destination 10.10.3.39")
        assert roles is not None
        by_ip = {r.ip: r.role for r in roles}
        assert by_ip["198.51.100.0"] == "source"
        assert by_ip["10.10.3.39"] == "dest"

    def test_passive_voice(self) -> None:
        roles = extract_ip_roles("The host 10.0.0.1 was targeted by 203.0.113.5")
        assert roles is not None
        by_ip = {r.ip: r.role for r in roles}
        assert by_ip["10.0.0.1"] == "dest"
        assert by_ip["203.0.113.5"] == "source"

    def test_no_ips(self) -> None:
        roles = extract_ip_roles("No IP addresses here")
        assert roles == []

    def test_unknown_role(self) -> None:
        roles = extract_ip_roles("The server at 10.0.0.1 is running")
        assert roles is not None
        assert len(roles) == 1
        assert roles[0].role == "unknown"


# ------------------------------------------------------------------
# extract_entities
# ------------------------------------------------------------------


class TestExtractEntities:
    """Named entity and CVE extraction."""

    def test_cve_extraction(self) -> None:
        result = extract_entities("Possible CVE-2021-44228 exploitation detected")
        assert result is not None
        assert "CVE-2021-44228" in result["cves"]

    def test_org_extraction(self) -> None:
        result = extract_entities("The source IP belongs to Google LLC")
        assert result is not None
        assert any("Google" in org for org in result["orgs"])

    def test_country_extraction(self) -> None:
        result = extract_entities("Traffic from Russia targeting US infrastructure")
        assert result is not None
        assert "Russia" in result["countries"]

    def test_filters_et_noise(self) -> None:
        result = extract_entities("ET SCAN detected from external host")
        assert result is not None
        assert "ET" not in result["orgs"]
        assert "SCAN" not in result["orgs"]

    def test_cve_not_in_orgs(self) -> None:
        result = extract_entities("Detected CVE-2021-44228 in the traffic")
        assert result is not None
        assert not any("CVE" in org for org in result["orgs"])
