"""Incident context builder — correlates device profiles, auth history, attack chains,
related tickets, and threat intel enrichment into a unified investigation view.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.profiler.device_profiler import DeviceProfile


@dataclass
class IncidentContext:
    """All context gathered for an incident investigation."""

    # Trigger
    trigger_type: str  # "notice", "ip_pair", "ticket"
    trigger: dict
    src_ip: str
    dest_ip: str
    sensor: str
    time_range: str

    # Device profiles (None if IP is public or profiling failed)
    src_profile: DeviceProfile | None = None
    dest_profile: DeviceProfile | None = None

    # Auth history between src ↔ dest
    kerberos_history: list[dict] = field(default_factory=list)
    ntlm_history: list[dict] = field(default_factory=list)

    # Attack chain (ATTACK::* notices for src_ip)
    attack_chain: list[dict] = field(default_factory=list)

    # Related Mantis tickets
    src_tickets: list[dict] = field(default_factory=list)
    dest_tickets: list[dict] = field(default_factory=list)

    # Threat intel enrichment (None if IP is private)
    src_enrichment: dict | None = None
    dest_enrichment: dict | None = None

    # Merged chronological timeline
    timeline: list[dict] = field(default_factory=list)

    # Errors from individual tracks (track_name → error message)
    errors: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Module-level imports — placed here so unit tests can patch them cleanly
# ---------------------------------------------------------------------------

from src.enricher.threat_intel import enrich_ip  # noqa: E402
from src.mantis.mantis_search import search as search_tickets  # noqa: E402
from src.profiler.device_profiler import profile_device  # noqa: E402
from src.querier.zeek_modules import MODULES  # noqa: E402
from src.querier.zeek_modules.base import (  # noqa: E402
    INDEX,
    is_private,
    query_opensearch,
    run_query,
)


def query_auth_history(
    src_ip: str,
    dest_ip: str,
    sensor: str,
    time_range: str,
) -> tuple[list[dict], list[dict]]:
    """Fetch Kerberos + NTLM records between src and dest IPs."""
    sp = {
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "sensor": sensor,
        "time_range": time_range,
        "limit": 200,
        "no_filters": False,
        "public_only": False,
        "raise_on_error": False,
    }
    krb = run_query(MODULES["kerberos"], dict(sp))
    ntlm = run_query(MODULES["ntlm"], dict(sp))
    return krb, ntlm


def query_attack_chain(src_ip: str, sensor: str, time_range: str) -> list[dict]:
    """Fetch ATTACK::* notices originating from src_ip in the time window."""
    notice_mod = MODULES["notice"]
    must: list = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
        {"terms": {"event.dataset": notice_mod.DATASETS}},
        {"term": {"source.ip": src_ip}},
        {"prefix": {"zeek.notice.note": "ATTACK::"}},
    ]
    if sensor != "all":
        must.append({"terms": {"host.name": [s.strip() for s in sensor.split(",")]}})
    body = {
        "size": 500,
        "query": {"bool": {"must": must}},
        "sort": [{"@timestamp": {"order": "asc"}}],
        "_source": notice_mod.SOURCE_FIELDS,
    }
    raw = query_opensearch(body, {"path": f"{INDEX}/_search", "method": "POST"})
    if not raw:
        return []
    hits = raw.get("hits", {}).get("hits", [])
    return [notice_mod.parse_hit(h["_source"]) for h in hits]


def build_timeline(ctx: IncidentContext) -> list[dict]:
    """Merge kerberos, ntlm, and attack chain events into chronological order."""
    events: list[dict] = []

    for rec in ctx.kerberos_history:
        events.append({"type": "kerberos", "timestamp": rec.get("timestamp", ""), **rec})
    for rec in ctx.ntlm_history:
        events.append({"type": "ntlm", "timestamp": rec.get("timestamp", ""), **rec})
    for rec in ctx.attack_chain:
        events.append({"type": "notice", "timestamp": rec.get("timestamp", ""), **rec})

    events.sort(key=lambda e: e.get("timestamp", ""))
    return events


def investigate(
    src_ip: str,
    dest_ip: str,
    sensor: str,
    time_range: str = "now-24h",
    *,
    trigger_type: str = "ip_pair",
    trigger: dict | None = None,
) -> IncidentContext:
    """Build full incident context for an IP pair.

    Runs 5 parallel tracks: src profile, dest profile, auth history,
    attack chain, and context gather (tickets + enrichment).
    Each track failure is caught and stored in ctx.errors — the context is
    always returned even with partial data.
    """
    ctx = IncidentContext(
        trigger_type=trigger_type,
        trigger=trigger or {"src_ip": src_ip, "dest_ip": dest_ip},
        src_ip=src_ip,
        dest_ip=dest_ip,
        sensor=sensor,
        time_range=time_range,
    )

    def _profile_src() -> None:
        if is_private(src_ip):
            ctx.src_profile = profile_device(src_ip, time_range=time_range, sensor=sensor)

    def _profile_dest() -> None:
        if is_private(dest_ip):
            ctx.dest_profile = profile_device(dest_ip, time_range=time_range, sensor=sensor)

    def _auth_history() -> None:
        ctx.kerberos_history, ctx.ntlm_history = query_auth_history(
            src_ip, dest_ip, sensor, time_range
        )

    def _attack_chain() -> None:
        ctx.attack_chain = query_attack_chain(src_ip, sensor, time_range)

    def _context_gather() -> None:
        ctx.src_tickets = search_tickets(src_ip)
        ctx.dest_tickets = search_tickets(dest_ip)
        if not is_private(src_ip):
            ctx.src_enrichment = enrich_ip(src_ip, offer_fp=False)
        if not is_private(dest_ip):
            ctx.dest_enrichment = enrich_ip(dest_ip, offer_fp=False)

    tracks = {
        "src_profile": _profile_src,
        "dest_profile": _profile_dest,
        "auth_history": _auth_history,
        "attack_chain": _attack_chain,
        "context_gather": _context_gather,
    }

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {pool.submit(fn): name for name, fn in tracks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                future.result()
            except Exception as exc:
                ctx.errors[name] = str(exc)

    ctx.timeline = build_timeline(ctx)
    return ctx
