"""Tests for the correlation engine — Phases 1 & 5: core orchestrator + integration."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.correlator.incident_context import (
    IncidentContext,
    build_timeline,
    investigate,
    query_attack_chain,
    query_auth_history,
)

# ---------------------------------------------------------------------------
# Fixtures (file-based)
# ---------------------------------------------------------------------------

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "correlator"


def _load_fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


KRB_HIT = _load_fixture("kerberos_hit.json")
NTLM_HIT = _load_fixture("ntlm_hit.json")
NOTICE_HIT = _load_fixture("notice_attack_chain_hit.json")

# ---------------------------------------------------------------------------
# Test data
# ---------------------------------------------------------------------------

PRIVATE_SRC = "10.200.50.15"
PRIVATE_DEST = "10.100.50.15"
PUBLIC_SRC = "8.8.8.8"
PUBLIC_DEST = "1.1.1.1"
SENSOR = "hedgehog-east-wenatchee"
TIME_RANGE = "now-24h"

KRB_RECORD = {"timestamp": "2024-06-01T10:00:00.000Z", "src_ip": PRIVATE_SRC}
NTLM_RECORD = {"timestamp": "2024-06-01T09:00:00.000Z", "src_ip": PRIVATE_SRC}
NOTICE_RECORD = {
    "timestamp": "2024-06-01T11:00:00.000Z",
    "notice_note": "ATTACK::Credential_Access",
}

MOCK_PROFILE = MagicMock()
MOCK_ENRICHMENT = {"ip": PUBLIC_SRC, "greynoise": {"classification": "malicious"}}

MOD = "src.correlator.incident_context"


def _base_patches(
    *,
    profile_side_effect=None,
    profile_return=None,
    krb: list | None = None,
    ntlm: list | None = None,
    chain_hits: list | None = None,
    tickets: list | None = None,
    enrichment: dict | None = None,
) -> list:
    """Return a stack of patch context managers covering all external calls."""
    if profile_side_effect is not None:
        profile_patch = patch(f"{MOD}.profile_device", side_effect=profile_side_effect)
    elif profile_return is not None:
        profile_patch = patch(f"{MOD}.profile_device", return_value=profile_return)
    else:
        profile_patch = patch(f"{MOD}.profile_device", return_value=MOCK_PROFILE)

    return [
        profile_patch,
        patch(f"{MOD}.query_auth_history", return_value=(krb or [], ntlm or [])),
        patch(f"{MOD}.query_opensearch", return_value={"hits": {"hits": chain_hits or []}}),
        patch(f"{MOD}.search_tickets", return_value=tickets or []),
        patch(f"{MOD}.enrich_ip", return_value=enrichment or {}),
    ]


# ---------------------------------------------------------------------------
# build_timeline
# ---------------------------------------------------------------------------


def test_timeline_chronological_ordering() -> None:
    ctx = IncidentContext(
        trigger_type="ip_pair",
        trigger={},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        kerberos_history=[KRB_RECORD],
        ntlm_history=[NTLM_RECORD],
        attack_chain=[NOTICE_RECORD],
    )
    timeline = build_timeline(ctx)
    timestamps = [e["timestamp"] for e in timeline]
    assert timestamps == sorted(timestamps)


def test_timeline_type_tags() -> None:
    ctx = IncidentContext(
        trigger_type="ip_pair",
        trigger={},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        kerberos_history=[KRB_RECORD],
        ntlm_history=[NTLM_RECORD],
        attack_chain=[NOTICE_RECORD],
    )
    timeline = build_timeline(ctx)
    assert {e["type"] for e in timeline} == {"kerberos", "ntlm", "notice"}


def test_timeline_empty() -> None:
    ctx = IncidentContext(
        trigger_type="ip_pair",
        trigger={},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
    )
    assert build_timeline(ctx) == []


def test_timeline_missing_timestamp_sorts_first() -> None:
    """Records without a timestamp key get empty string, which sorts before any ISO date."""
    ctx = IncidentContext(
        trigger_type="ip_pair",
        trigger={},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        kerberos_history=[{"src_ip": PRIVATE_SRC}],  # no timestamp
        attack_chain=[NOTICE_RECORD],
    )
    timeline = build_timeline(ctx)
    assert timeline[0]["type"] == "kerberos"


def test_timeline_does_not_mutate_source_records() -> None:
    original = {"timestamp": "2024-06-01T10:00:00.000Z", "src_ip": PRIVATE_SRC}
    ctx = IncidentContext(
        trigger_type="ip_pair",
        trigger={},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        kerberos_history=[original],
    )
    build_timeline(ctx)
    assert "type" not in original


# ---------------------------------------------------------------------------
# investigate() — IP routing logic
# ---------------------------------------------------------------------------


def test_investigate_both_private() -> None:
    patches = _base_patches(krb=[KRB_RECORD], ntlm=[NTLM_RECORD])
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert ctx.src_profile is not None
    assert ctx.dest_profile is not None
    assert len(ctx.kerberos_history) == 1
    assert len(ctx.ntlm_history) == 1
    assert ctx.src_enrichment is None
    assert ctx.dest_enrichment is None
    assert ctx.errors == {}


def test_investigate_one_public() -> None:
    """Private src → profiled; public dest → enriched, not profiled."""
    patches = _base_patches(enrichment=MOCK_ENRICHMENT)
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PUBLIC_DEST, SENSOR, TIME_RANGE)

    assert ctx.src_profile is not None
    assert ctx.dest_profile is None
    assert ctx.dest_enrichment is not None
    assert ctx.src_enrichment is None


def test_investigate_both_public() -> None:
    """Both public → no profiling, both enrichments populated."""
    patches = _base_patches(enrichment=MOCK_ENRICHMENT)
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PUBLIC_SRC, PUBLIC_DEST, SENSOR, TIME_RANGE)

    assert ctx.src_profile is None
    assert ctx.dest_profile is None
    assert ctx.src_enrichment is not None
    assert ctx.dest_enrichment is not None


def test_investigate_track_failure_isolated() -> None:
    """Failure in src_profile track stores error; other tracks succeed."""
    patches = _base_patches(profile_side_effect=ValueError("sensor mismatch"))
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    failed = ctx.errors.get("src_profile", "") + ctx.errors.get("dest_profile", "")
    assert "sensor mismatch" in failed
    assert "auth_history" not in ctx.errors
    assert "attack_chain" not in ctx.errors
    assert "context_gather" not in ctx.errors


def test_investigate_no_auth_history() -> None:
    patches = _base_patches(krb=[], ntlm=[])
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert ctx.kerberos_history == []
    assert ctx.ntlm_history == []
    assert "auth_history" not in ctx.errors


def test_investigate_returns_context_on_full_failure() -> None:
    """investigate() always returns IncidentContext even when all tracks fail."""
    with (
        patch(f"{MOD}.profile_device", side_effect=RuntimeError("ES down")),
        patch(f"{MOD}.query_auth_history", side_effect=RuntimeError("ES down")),
        patch(f"{MOD}.query_opensearch", side_effect=RuntimeError("ES down")),
        patch(f"{MOD}.search_tickets", side_effect=RuntimeError("Mantis down")),
        patch(f"{MOD}.enrich_ip", return_value={}),
    ):
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert isinstance(ctx, IncidentContext)
    assert len(ctx.errors) > 0
    assert ctx.timeline == []


# ---------------------------------------------------------------------------
# investigate() — metadata
# ---------------------------------------------------------------------------


def test_investigate_default_trigger_and_time_range() -> None:
    patches = _base_patches()
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR)

    assert ctx.trigger == {"src_ip": PRIVATE_SRC, "dest_ip": PRIVATE_DEST}
    assert ctx.trigger_type == "ip_pair"
    assert ctx.time_range == "now-24h"


def test_investigate_custom_trigger() -> None:
    custom_trigger = {"ticket_id": 1234}
    patches = _base_patches()
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(
            PRIVATE_SRC,
            PRIVATE_DEST,
            SENSOR,
            trigger_type="ticket",
            trigger=custom_trigger,
        )

    assert ctx.trigger == custom_trigger
    assert ctx.trigger_type == "ticket"


def test_investigate_timeline_populated() -> None:
    patches = _base_patches(krb=[KRB_RECORD], ntlm=[NTLM_RECORD])
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert len(ctx.timeline) == 2
    timestamps = [e["timestamp"] for e in ctx.timeline]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# query_auth_history — search_params contract
# ---------------------------------------------------------------------------


def test_query_auth_history_search_params() -> None:
    """run_query is called with correct search_params for both kerberos and ntlm."""
    with patch(f"{MOD}.run_query", return_value=[]) as mock_rq:
        query_auth_history(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert mock_rq.call_count == 2
    _, first_call_kwargs = mock_rq.call_args_list[0]
    first_call_pos = mock_rq.call_args_list[0][0]
    # Extract the search_params dict (second positional arg)
    sp = first_call_pos[1]
    assert sp["src_ip"] == PRIVATE_SRC
    assert sp["dest_ip"] == PRIVATE_DEST
    assert sp["sensor"] == SENSOR
    assert sp["time_range"] == TIME_RANGE
    assert sp["limit"] == 200
    assert sp["raise_on_error"] is False


def test_query_auth_history_both_protocols_queried() -> None:
    """Both kerberos and ntlm modules are passed to run_query."""
    from src.querier.zeek_modules import MODULES

    with patch(f"{MOD}.run_query", return_value=[]) as mock_rq:
        query_auth_history(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    called_modules = [c[0][0] for c in mock_rq.call_args_list]
    assert MODULES["kerberos"] in called_modules
    assert MODULES["ntlm"] in called_modules


def test_query_auth_history_returns_tuple() -> None:
    with patch(f"{MOD}.run_query", side_effect=[[KRB_RECORD], [NTLM_RECORD]]):
        krb, ntlm = query_auth_history(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert krb == [KRB_RECORD]
    assert ntlm == [NTLM_RECORD]


# ---------------------------------------------------------------------------
# query_attack_chain — sensor filter and ES response parsing
# ---------------------------------------------------------------------------


def test_query_attack_chain_includes_sensor_filter() -> None:
    """When sensor is not 'all', a host.name terms filter is added to the query."""
    with patch(f"{MOD}.query_opensearch", return_value={"hits": {"hits": []}}) as mock_qs:
        query_attack_chain(PRIVATE_SRC, SENSOR, TIME_RANGE)

    body = mock_qs.call_args[0][0]
    must_clauses = body["query"]["bool"]["must"]
    host_filter = next(
        (c for c in must_clauses if "terms" in c and "host.name" in c["terms"]), None
    )
    assert host_filter is not None
    assert SENSOR in host_filter["terms"]["host.name"]


def test_query_attack_chain_omits_sensor_filter_for_all() -> None:
    """When sensor='all', no host.name filter is added."""
    with patch(f"{MOD}.query_opensearch", return_value={"hits": {"hits": []}}) as mock_qs:
        query_attack_chain(PRIVATE_SRC, "all", TIME_RANGE)

    body = mock_qs.call_args[0][0]
    must_clauses = body["query"]["bool"]["must"]
    host_filter = next(
        (c for c in must_clauses if "terms" in c and "host.name" in c.get("terms", {})), None
    )
    assert host_filter is None


def test_query_attack_chain_empty_response() -> None:
    with patch(f"{MOD}.query_opensearch", return_value=None):
        result = query_attack_chain(PRIVATE_SRC, SENSOR, TIME_RANGE)
    assert result == []


def test_query_attack_chain_parses_fixture_hit() -> None:
    """parse_hit is applied to each ES hit — spot-check against the fixture."""
    raw_hit = NOTICE_HIT
    with patch(f"{MOD}.query_opensearch", return_value={"hits": {"hits": [raw_hit]}}):
        result = query_attack_chain(PRIVATE_SRC, SENSOR, TIME_RANGE)

    assert len(result) == 1
    parsed = result[0]
    assert parsed["timestamp"] == "2024-06-01T11:00:00.000Z"
    assert parsed["notice_note"] == "ATTACK::Credential_Access"
    assert parsed["src_ip"] == PRIVATE_SRC
    assert parsed["dest_ip"] == PRIVATE_DEST


def test_query_attack_chain_attack_prefix_filter() -> None:
    """Query includes a prefix filter for ATTACK:: notices."""
    with patch(f"{MOD}.query_opensearch", return_value={"hits": {"hits": []}}) as mock_qs:
        query_attack_chain(PRIVATE_SRC, SENSOR, TIME_RANGE)

    body = mock_qs.call_args[0][0]
    must_clauses = body["query"]["bool"]["must"]
    prefix_filter = next(
        (c for c in must_clauses if "prefix" in c and "zeek.notice.note" in c["prefix"]), None
    )
    assert prefix_filter is not None
    assert prefix_filter["prefix"]["zeek.notice.note"] == "ATTACK::"


# ---------------------------------------------------------------------------
# Integration: investigate() with fixture-based ES responses
# ---------------------------------------------------------------------------


def test_investigate_parses_attack_chain_from_fixture() -> None:
    """End-to-end: attack chain hits from fixture produce correctly typed timeline events."""
    patches = _base_patches(
        chain_hits=[NOTICE_HIT],
    )
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    notice_events = [e for e in ctx.timeline if e["type"] == "notice"]
    assert len(notice_events) == 1
    assert notice_events[0]["notice_note"] == "ATTACK::Credential_Access"


def test_investigate_tickets_populated() -> None:
    """Mantis tickets are stored per-IP in src_tickets / dest_tickets."""
    mock_ticket = {"id": 42, "summary": f"Suspicious activity from {PRIVATE_SRC}"}
    patches = _base_patches(tickets=[mock_ticket])
    with patches[0], patches[1], patches[2], patches[3], patches[4]:
        ctx = investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    assert ctx.src_tickets == [mock_ticket]
    assert ctx.dest_tickets == [mock_ticket]


def test_investigate_context_gather_skips_enrichment_for_private() -> None:
    """enrich_ip is never called when both IPs are private."""
    patches = _base_patches()
    with patches[0], patches[1], patches[2], patches[3], patches[4] as mock_enrich:
        investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    mock_enrich.assert_not_called()


# ---------------------------------------------------------------------------
# MCP tool — JSON serialization and error handling
# ---------------------------------------------------------------------------

# Load the MCP server module via its file path (it is not an installed package).
_MCP_SERVER_PATH = Path(__file__).parent.parent / "mcp" / "opensearch" / "server.py"

try:
    import importlib.util as _ilu

    _spec = _ilu.spec_from_file_location("_mcp_server", _MCP_SERVER_PATH)
    mcp_server = _ilu.module_from_spec(_spec)  # type: ignore[arg-type]
    _spec.loader.exec_module(mcp_server)  # type: ignore[union-attr]
    _MCP_AVAILABLE = True
except Exception:
    mcp_server = None  # type: ignore[assignment]
    _MCP_AVAILABLE = False

_skip_no_mcp = pytest.mark.skipif(not _MCP_AVAILABLE, reason="MCP server not importable")


def _make_incident_context(**overrides) -> IncidentContext:
    """Return a minimal IncidentContext suitable for asdict() serialization."""
    defaults = dict(
        trigger_type="ip_pair",
        trigger={"src_ip": PRIVATE_SRC, "dest_ip": PRIVATE_DEST},
        src_ip=PRIVATE_SRC,
        dest_ip=PRIVATE_DEST,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        kerberos_history=[KRB_RECORD],
        ntlm_history=[NTLM_RECORD],
        attack_chain=[NOTICE_RECORD],
        src_tickets=[],
        dest_tickets=[],
        src_enrichment=None,
        dest_enrichment=None,
        timeline=[],
        errors={},
    )
    defaults.update(overrides)
    return IncidentContext(**defaults)


@_skip_no_mcp
def test_mcp_investigate_returns_ok_json() -> None:
    """MCP investigate tool returns JSON with status='ok' and all top-level keys."""
    ctx = _make_incident_context()
    with patch("src.correlator.incident_context.investigate", return_value=ctx):
        result_str = mcp_server.investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    result = json.loads(result_str)
    assert result["status"] == "ok"
    data = result["data"]
    for key in (
        "src_ip",
        "dest_ip",
        "sensor",
        "time_range",
        "trigger_type",
        "kerberos_history",
        "ntlm_history",
        "attack_chain",
        "errors",
    ):
        assert key in data, f"Missing key: {key}"


@_skip_no_mcp
def test_mcp_investigate_profile_trimmed() -> None:
    """Profile dicts are trimmed to compact summaries — full DeviceProfile keys stripped."""
    from src.profiler.device_profiler import DeviceProfile

    profile = DeviceProfile(
        ip=PRIVATE_SRC,
        sensor=SENSOR,
        time_range=TIME_RANGE,
        role="workstation",
        confidence=0.85,
        os_family="Windows",
        hostname="workstation01",
    )
    ctx = _make_incident_context(src_profile=profile)
    with patch("src.correlator.incident_context.investigate", return_value=ctx):
        result_str = mcp_server.investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    result = json.loads(result_str)
    assert result["status"] == "ok"
    trimmed = result["data"]["src_profile"]
    # Only summary keys present — full DeviceProfile fields like dest_port_distribution stripped
    expected_keys = {
        "ip",
        "hostname",
        "role",
        "confidence",
        "os_family",
        "software",
        "users",
        "inbound_services",
    }
    assert set(trimmed.keys()) == expected_keys
    assert trimmed["role"] == "workstation"
    assert trimmed["ip"] == PRIVATE_SRC
    assert "dest_port_distribution" not in trimmed
    assert "bytes_sent" not in trimmed


@_skip_no_mcp
def test_mcp_investigate_error_json() -> None:
    """MCP investigate tool returns JSON with status='error' when backend raises."""
    with patch(
        "src.correlator.incident_context.investigate",
        side_effect=RuntimeError("OpenSearch unreachable"),
    ):
        result_str = mcp_server.investigate(PRIVATE_SRC, PRIVATE_DEST, SENSOR, TIME_RANGE)

    result = json.loads(result_str)
    assert result["status"] == "error"
    assert "OpenSearch unreachable" in result["message"]


@_skip_no_mcp
def test_mcp_investigate_null_profiles_preserved() -> None:
    """None profiles (public IPs) are preserved as null in JSON — not trimmed."""
    ctx = _make_incident_context(src_profile=None, dest_profile=None)
    with patch("src.correlator.incident_context.investigate", return_value=ctx):
        result_str = mcp_server.investigate(PUBLIC_SRC, PUBLIC_DEST, SENSOR, TIME_RANGE)

    result = json.loads(result_str)
    assert result["status"] == "ok"
    assert result["data"]["src_profile"] is None
    assert result["data"]["dest_profile"] is None
