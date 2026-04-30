"""Tests for pure helper functions in apps/mantis_web/.

Covers:
  - data.py pure functions: fmt_attack, country_flag, days_between, _malicious_row
  - app.py pure helpers: _page_args, _sort_rows
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# data.py pure functions
# The module loads JSON files at import time, so we mock _load/_load_optional
# before importing any symbol from data.py.
# ---------------------------------------------------------------------------


def _import_data_with_empty_files():
    """Import apps.mantis_web.data with all file loading stubbed out."""

    # Remove cached module so the patched version is freshly imported
    for key in list(sys.modules):
        if "apps.mantis_web" in key:
            del sys.modules[key]

    with patch("builtins.open", MagicMock()):
        with patch("json.load", return_value=[]):
            import apps.mantis_web.data as data_mod

    return data_mod


# ---------------------------------------------------------------------------
# fmt_attack
# ---------------------------------------------------------------------------


class TestFmtAttack:
    def test_underscore_to_space(self) -> None:
        from apps.mantis_web.data import fmt_attack

        assert fmt_attack("port_scan") == "Port Scan"

    def test_title_case(self) -> None:
        from apps.mantis_web.data import fmt_attack

        assert fmt_attack("brute_force_login") == "Brute Force Login"

    def test_no_underscore(self) -> None:
        from apps.mantis_web.data import fmt_attack

        assert fmt_attack("malware") == "Malware"


# ---------------------------------------------------------------------------
# country_flag
# ---------------------------------------------------------------------------


class TestCountryFlag:
    def test_us_flag(self) -> None:
        from apps.mantis_web.data import country_flag

        result = country_flag("US")
        assert len(result) == 2  # two regional indicator symbols

    def test_gb_flag(self) -> None:
        from apps.mantis_web.data import country_flag

        result = country_flag("GB")
        assert result != ""

    def test_empty_string_returns_empty(self) -> None:
        from apps.mantis_web.data import country_flag

        assert country_flag("") == ""

    def test_non_two_char_returns_empty(self) -> None:
        from apps.mantis_web.data import country_flag

        assert country_flag("USA") == ""

    def test_lowercase_works(self) -> None:
        from apps.mantis_web.data import country_flag

        assert country_flag("de") == country_flag("DE")


# ---------------------------------------------------------------------------
# days_between
# ---------------------------------------------------------------------------


class TestDaysBetween:
    def test_same_date(self) -> None:
        from apps.mantis_web.data import days_between

        assert days_between("2024-01-01", "2024-01-01") == 0

    def test_one_week(self) -> None:
        from apps.mantis_web.data import days_between

        assert days_between("2024-01-01", "2024-01-08") == 7

    def test_invalid_date_returns_zero(self) -> None:
        from apps.mantis_web.data import days_between

        assert days_between("", "") == 0

    def test_malformed_date_returns_zero(self) -> None:
        from apps.mantis_web.data import days_between

        assert days_between("not-a-date", "2024-01-01") == 0


# ---------------------------------------------------------------------------
# _malicious_row
# ---------------------------------------------------------------------------


class TestMaliciousRow:
    def test_basic_fields(self) -> None:
        from apps.mantis_web.data import _malicious_row

        raw = {
            "ip": "198.51.100.1",
            "ticket_count": 5,
            "attack_types": ["port_scan"],
            "blocklists": ["spamhaus_drop"],
            "country": "RU",
            "first_seen": "2024-01-01",
            "last_seen": "2024-01-15",
        }
        row = _malicious_row(raw)
        assert row["ip"] == "198.51.100.1"
        assert row["ticket_count"] == 5
        assert "Port Scan" in row["attack_str"]
        assert "spamhaus_drop" in row["blocklist_str"]

    def test_missing_optional_fields_use_defaults(self) -> None:
        from apps.mantis_web.data import _malicious_row

        raw = {"ip": "203.0.113.1"}
        row = _malicious_row(raw)
        assert row["ip"] == "203.0.113.1"
        assert row["isp"] == "—"
        assert row["asn"] == "—"
        assert row["attack_types"] == []

    def test_empty_blocklists_shows_dash(self) -> None:
        from apps.mantis_web.data import _malicious_row

        raw = {"ip": "1.2.3.4", "blocklists": []}
        row = _malicious_row(raw)
        assert row["blocklist_str"] == "—"


# ---------------------------------------------------------------------------
# app.py helpers — _page_args and _sort_rows
# Imported via a lightweight mock of the data module to avoid JSON file reads.
# ---------------------------------------------------------------------------


def _get_app_helpers():
    """Import _page_args and _sort_rows with data module mocked."""
    for key in list(sys.modules):
        if "apps.mantis_web" in key:
            del sys.modules[key]

    mock_data = MagicMock()
    mock_data.MALICIOUS_ROWS = []
    mock_data.FP_ROWS = []
    mock_data.INFRA_ROWS = []
    mock_data.DNS_RESOLVER_ROWS = []
    mock_data.UNDETERMINED_ROWS = []
    mock_data.ALL_ATTACK_TYPES = []
    mock_data.ALL_BLOCKLISTS = []
    mock_data.ALL_FP_CATEGORIES = []
    mock_data.ALL_INFRA_CATEGORIES = []
    mock_data.TICKETS_BY_ID = {}
    mock_data.MALICIOUS_BY_IP = {}
    mock_data.FP_BY_IP = {}
    mock_data.classify_ip = MagicMock(return_value="unknown")
    mock_data.fmt_attack = MagicMock(side_effect=lambda s: s)
    mock_data.get_tickets_for_ip = MagicMock(return_value=[])
    mock_data._fp_row = MagicMock(return_value={})
    mock_data._malicious_row = MagicMock(return_value={})

    with patch.dict(sys.modules, {"apps.mantis_web.data": mock_data}):
        import apps.mantis_web.app as app_mod

    return app_mod._page_args, app_mod._sort_rows


class TestPageArgs:
    def setup_method(self) -> None:
        self._page_args, _ = _get_app_helpers()

    def test_defaults(self) -> None:
        page, per_page = self._page_args({})
        assert page == 1
        assert per_page == 50

    def test_custom_page(self) -> None:
        page, per_page = self._page_args({"page": "3"})
        assert page == 3

    def test_page_below_one_clamped(self) -> None:
        page, _ = self._page_args({"page": "0"})
        assert page == 1

    def test_invalid_page_defaults_to_one(self) -> None:
        page, _ = self._page_args({"page": "abc"})
        assert page == 1

    def test_valid_per_page(self) -> None:
        _, per_page = self._page_args({"per_page": "100"})
        assert per_page == 100

    def test_invalid_per_page_defaults(self) -> None:
        _, per_page = self._page_args({"per_page": "999"})
        assert per_page == 50


# ---------------------------------------------------------------------------
# get_tickets_for_ip — must use TICKETS_BY_IP index, not scan _raw_tickets
# ---------------------------------------------------------------------------


class TestGetTicketsForIp:
    def test_returns_ticket_for_known_ip(self) -> None:
        import apps.mantis_web.data as data_mod

        ticket = {"id": "1", "created_at": "2024-01-01", "ips": ["1.2.3.4"]}
        with (
            patch.object(data_mod, "TICKETS_BY_IP", {"1.2.3.4": ["1"]}),
            patch.object(data_mod, "TICKETS_BY_ID", {"1": ticket}),
        ):
            result = data_mod.get_tickets_for_ip("1.2.3.4")
        assert result == [ticket]

    def test_returns_empty_for_unknown_ip(self) -> None:
        import apps.mantis_web.data as data_mod

        with (
            patch.object(data_mod, "TICKETS_BY_IP", {}),
            patch.object(data_mod, "TICKETS_BY_ID", {}),
        ):
            result = data_mod.get_tickets_for_ip("9.9.9.9")
        assert result == []

    def test_sorted_newest_first(self) -> None:
        import apps.mantis_web.data as data_mod

        t1 = {"id": "1", "created_at": "2024-01-01"}
        t2 = {"id": "2", "created_at": "2024-06-01"}
        t3 = {"id": "3", "created_at": "2024-03-01"}
        with (
            patch.object(data_mod, "TICKETS_BY_IP", {"1.2.3.4": ["1", "2", "3"]}),
            patch.object(data_mod, "TICKETS_BY_ID", {"1": t1, "2": t2, "3": t3}),
        ):
            result = data_mod.get_tickets_for_ip("1.2.3.4")
        assert result[0]["id"] == "2"
        assert result[-1]["id"] == "1"

    def test_skips_missing_ticket_ids(self) -> None:
        import apps.mantis_web.data as data_mod

        ticket = {"id": "1", "created_at": "2024-01-01"}
        with (
            patch.object(data_mod, "TICKETS_BY_IP", {"1.2.3.4": ["1", "999"]}),
            patch.object(data_mod, "TICKETS_BY_ID", {"1": ticket}),
        ):
            result = data_mod.get_tickets_for_ip("1.2.3.4")
        assert len(result) == 1
        assert result[0]["id"] == "1"


class TestSortRows:
    def setup_method(self) -> None:
        _, self._sort_rows = _get_app_helpers()

    def _rows(self) -> list[dict]:
        return [
            {"ip": "3.3.3.3", "ticket_count": 3},
            {"ip": "1.1.1.1", "ticket_count": 10},
            {"ip": "2.2.2.2", "ticket_count": 1},
        ]

    def test_sort_by_ticket_count_desc(self) -> None:
        rows = self._sort_rows(self._rows(), {"sort": "ticket_count", "order": "desc"})
        assert rows[0]["ticket_count"] == 10

    def test_sort_by_ticket_count_asc(self) -> None:
        rows = self._sort_rows(self._rows(), {"sort": "ticket_count", "order": "asc"})
        assert rows[0]["ticket_count"] == 1

    def test_sort_by_ip_string(self) -> None:
        rows = self._sort_rows(self._rows(), {"sort": "ip", "order": "asc"})
        assert rows[0]["ip"] == "1.1.1.1"

    def test_empty_rows(self) -> None:
        rows = self._sort_rows([], {"sort": "ticket_count", "order": "desc"})
        assert rows == []

    def test_default_sort_is_desc(self) -> None:
        rows = self._sort_rows(self._rows(), {})
        assert rows[0]["ticket_count"] == 10
