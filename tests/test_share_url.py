"""Tests for src/utils/share_url.py — Rison encoding, KQL building, URL generation."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utils.share_url import (
    ShareContext,
    build_dashboards_path,
    build_kql,
    build_pisces_url,
    rison_encode,
    shorten_dashboards_url,
)

# ---------------------------------------------------------------------------
# rison_encode
# ---------------------------------------------------------------------------


class TestRisonEncode:
    def test_none(self) -> None:
        assert rison_encode(None) == "!n"

    def test_bool_true(self) -> None:
        assert rison_encode(True) == "!t"

    def test_bool_false(self) -> None:
        assert rison_encode(False) == "!f"

    def test_int(self) -> None:
        assert rison_encode(42) == "42"

    def test_float(self) -> None:
        assert rison_encode(3.14) == "3.14"

    def test_safe_string(self) -> None:
        assert rison_encode("hello") == "hello"

    def test_string_with_spaces(self) -> None:
        assert rison_encode("hello world") == "'hello world'"

    def test_string_with_single_quote(self) -> None:
        assert rison_encode("it's") == "'it!'s'"

    def test_string_with_bang(self) -> None:
        # '!' is not in the conservative safe set, so it gets quoted
        assert rison_encode("a!b") == "'a!!b'"

    def test_empty_list(self) -> None:
        assert rison_encode([]) == "!()"

    def test_list(self) -> None:
        assert rison_encode(["a", "b"]) == "!(a,b)"

    def test_empty_dict(self) -> None:
        assert rison_encode({}) == "()"

    def test_dict(self) -> None:
        result = rison_encode({"key": "val", "num": 1})
        assert result == "(key:val,num:1)"

    def test_nested(self) -> None:
        result = rison_encode({"query": {"language": "kuery", "query": "source.ip:1.2.3.4"}})
        assert "language:kuery" in result
        assert "'source.ip:1.2.3.4'" in result

    def test_time_state(self) -> None:
        obj = {
            "time": {"from": "2026-04-07T15:43:00Z", "to": "2026-04-08T15:43:00Z"},
        }
        result = rison_encode(obj)
        # Timestamps contain ':' so they get single-quoted
        assert "from:'2026-04-07T15:43:00Z'" in result
        assert "to:'2026-04-08T15:43:00Z'" in result


# ---------------------------------------------------------------------------
# build_kql
# ---------------------------------------------------------------------------


class TestBuildKql:
    def test_empty_context(self) -> None:
        ctx = ShareContext()
        assert build_kql(ctx) == ""

    def test_src_ip_only(self) -> None:
        ctx = ShareContext(src_ip="10.0.0.1")
        assert build_kql(ctx) == "source.ip:10.0.0.1"

    def test_log_type_conn(self) -> None:
        ctx = ShareContext(log_type="conn")
        assert build_kql(ctx) == "event.dataset:conn"

    def test_suricata_special_case(self) -> None:
        ctx = ShareContext(log_type="suricata_alert")
        kql = build_kql(ctx)
        assert "event.module:suricata" in kql
        assert "event.dataset:alert" in kql

    def test_sensor_all_omitted(self) -> None:
        ctx = ShareContext(sensor="all", src_ip="10.0.0.1")
        assert "host.name" not in build_kql(ctx)

    def test_sensor_single(self) -> None:
        ctx = ShareContext(sensor="hedgehog-east")
        assert build_kql(ctx) == "host.name:hedgehog-east"

    def test_sensor_multi(self) -> None:
        ctx = ShareContext(sensor="hedgehog-east,hedgehog-west")
        kql = build_kql(ctx)
        assert "host.name:hedgehog-east" in kql
        assert "host.name:hedgehog-west" in kql

    def test_ip_pivot_uses_or(self) -> None:
        ctx = ShareContext(src_ip="10.0.0.1", page_type="ip_pivot")
        kql = build_kql(ctx)
        assert "source.ip:10.0.0.1 OR destination.ip:10.0.0.1" in kql

    def test_extra_params_notice(self) -> None:
        ctx = ShareContext(
            log_type="notice",
            extra_params={"notice_note": "Scan::Port_Scan"},
        )
        assert "zeek.notice.note:Scan::Port_Scan" in build_kql(ctx)

    def test_extra_params_dns(self) -> None:
        ctx = ShareContext(
            log_type="dns",
            extra_params={"dns_query": "evil.com"},
        )
        assert "zeek.dns.query:evil.com" in build_kql(ctx)

    def test_extra_params_empty_value_skipped(self) -> None:
        ctx = ShareContext(
            log_type="dns",
            extra_params={"dns_query": "", "rcode": None},
        )
        assert "zeek.dns" not in build_kql(ctx)

    def test_combined(self) -> None:
        ctx = ShareContext(
            src_ip="10.0.0.1",
            sensor="hedgehog-east",
            log_type="conn",
        )
        kql = build_kql(ctx)
        assert "event.dataset:conn" in kql
        assert "source.ip:10.0.0.1" in kql
        assert "host.name:hedgehog-east" in kql


# ---------------------------------------------------------------------------
# build_pisces_url
# ---------------------------------------------------------------------------


class TestBuildPiscesUrl:
    def test_overview(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
        )
        url = build_pisces_url(ctx)
        assert url.startswith("/")
        assert "from=2026-04-07" in url
        assert "to=2026-04-08" in url

    def test_ip_pivot(self) -> None:
        ctx = ShareContext(src_ip="10.0.0.1", page_type="ip_pivot")
        url = build_pisces_url(ctx)
        assert "/ip/10.0.0.1" in url

    def test_log_view(self) -> None:
        ctx = ShareContext(log_type="dns", page_type="log")
        url = build_pisces_url(ctx)
        assert "/log/dns" in url

    def test_script_name(self) -> None:
        ctx = ShareContext(page_type="overview")
        url = build_pisces_url(ctx, script_name="/opensearch")
        assert url.startswith("/opensearch/")

    def test_sensor_all_omitted(self) -> None:
        ctx = ShareContext(sensor="all")
        url = build_pisces_url(ctx)
        assert "sensor" not in url

    def test_extra_params_included(self) -> None:
        ctx = ShareContext(
            log_type="notice",
            page_type="log",
            extra_params={"notice_note": "Scan::Port_Scan"},
        )
        url = build_pisces_url(ctx)
        assert "notice_note=Scan" in url


# ---------------------------------------------------------------------------
# build_dashboards_path
# ---------------------------------------------------------------------------


class TestBuildDashboardsPath:
    def test_starts_with_app_discover(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
        )
        path = build_dashboards_path(ctx)
        assert path.startswith("/app/discover#/")

    def test_contains_g_and_a(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
            src_ip="10.0.0.1",
        )
        path = build_dashboards_path(ctx)
        assert "_g=" in path
        assert "_a=" in path

    def test_time_in_g_state(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
        )
        path = build_dashboards_path(ctx)
        assert "2026-04-07T00:00:00Z" in path
        assert "2026-04-08T00:00:00Z" in path

    def test_kql_in_a_state(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
            src_ip="10.0.0.1",
            log_type="conn",
        )
        path = build_dashboards_path(ctx)
        assert "source.ip:10.0.0.1" in path
        assert "event.dataset:conn" in path

    def test_index_pattern(self) -> None:
        ctx = ShareContext(
            time_from="2026-04-07T00:00:00Z",
            time_to="2026-04-08T00:00:00Z",
        )
        path = build_dashboards_path(ctx)
        assert "arkime_sessions3-*" in path


# ---------------------------------------------------------------------------
# shorten_dashboards_url
# ---------------------------------------------------------------------------


class TestShortenDashboardsUrl:
    @patch("src.utils.share_url.requests.post")
    def test_success(self, mock_post: MagicMock) -> None:
        mock_post.return_value = MagicMock(
            ok=True,
            json=lambda: {"urlId": "abc123"},
        )
        result = shorten_dashboards_url("/app/discover#/...", "https://example.com", ("u", "p"))
        assert result == "https://example.com/goto/abc123"

    @patch("src.utils.share_url.requests.post")
    def test_failure_returns_none(self, mock_post: MagicMock) -> None:
        mock_post.return_value = MagicMock(ok=False)
        result = shorten_dashboards_url("/app/discover#/...", "https://example.com", ("u", "p"))
        assert result is None

    @patch("src.utils.share_url.requests.post", side_effect=Exception("timeout"))
    def test_exception_returns_none(self, mock_post: MagicMock) -> None:
        result = shorten_dashboards_url("/app/discover#/...", "https://example.com", ("u", "p"))
        assert result is None
