"""Tests for the correlation engine — Phase 1: core orchestrator."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.correlator.incident_context import IncidentContext, build_timeline, investigate

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
        patch(f"{MOD}._query_auth_history", return_value=(krb or [], ntlm or [])),
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
        patch(f"{MOD}._query_auth_history", side_effect=RuntimeError("ES down")),
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
