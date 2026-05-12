#!/usr/bin/env python3
"""Core query execution: deduplication, post-filtering, and run_query entrypoint."""

import hashlib
import json
import os
from collections import defaultdict

from src.querier.builder import _remap_clause, build_base_query
from src.querier.client import console, query_opensearch, query_opensearch_async
from src.utils.cache import cache_path as _cache_path_util
from src.utils.cache import load_cache, save_cache
from src.utils.format import fmt_bytes, fmt_dur

# Backwards-compatible aliases — zeek modules import these names from .base
_fmt_bytes = fmt_bytes
_fmt_dur = fmt_dur

# Project root — four dirname() calls up from src/querier/runner.py
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILTERS_DIR = os.path.join(_BASE, "filters")

# Fetch this many times the requested limit when post-filters are active.
_OVERFETCH_MULTIPLIER = 3


def _first(val):
    """Return val as-is if scalar, or the first element if it's a list."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


def _sensor_str(rec: dict) -> str:
    """Format the sensor(s) column for display."""
    sensors = rec.get("sensors")
    vals = sensors if sensors else ([rec["sensor"]] if rec.get("sensor") else [])
    return ", ".join(v.removeprefix("hedgehog-") for v in vals)


def _cache_path(args_hash: str) -> str:
    return _cache_path_util(f"opensearch_{args_hash}.json")


_save_cache = save_cache
_load_cache = load_cache

# Cache: (raw_must_not, remapped) — invalidates when load_filters returns a new list object.
_remap_cache: tuple[list, list] | None = None


def load_with_remap(filters_dir: str) -> tuple:
    """Load filters and remap field names. Returns (must_not, fcount, errors)."""
    global _remap_cache
    from src.querier.filter_loader import load_filters

    filter_result = load_filters(filters_dir)
    raw = filter_result["must_not"]
    if _remap_cache is None or _remap_cache[0] is not raw:
        _remap_cache = (raw, [_remap_clause(c) for c in raw])
    return _remap_cache[1], filter_result["filter_count"], filter_result["errors"]


def deduplicate_zeek(records: list, key_fn) -> list:
    """Deduplicate records by key_fn, keeping the most recent per group.

    Sorts output by descending frequency so highest-volume flows appear first.
    """
    grouped: dict = defaultdict(list)
    for rec in records:
        key = key_fn(rec)
        grouped[key].append(rec)

    deduped = []
    for _key, group in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        rep = max(group, key=lambda r: r["timestamp"]).copy()
        rep["freq"] = len(group)
        if len(group) == 1:
            rep["sensors"] = [rep["sensor"]] if rep.get("sensor") else []
        else:
            rep["sensors"] = sorted({r["sensor"] for r in group if r.get("sensor")})
        deduped.append(rep)

    return deduped


def run_query(module, search_params: dict) -> list:
    """Execute a full query cycle: load filters, build query, fetch, parse, dedup."""
    if search_params.get("no_filters"):
        must_not: list = []
        console.print("[yellow]--no-filters: all false positive filters disabled[/yellow]")
    else:
        must_not, fcount, errors = load_with_remap(FILTERS_DIR)
        console.print("[dim]Loading false positive filters...[/dim]")
        console.print(
            f"[dim]Loaded {fcount} filter file(s) → {len(must_not)} must_not clause(s)[/dim]"
        )
        for err in errors:
            console.print(f"[yellow]Filter warning: {err}[/yellow]")

    sensors: list | None = None
    sensor_val = search_params.get("sensor", "all")
    if sensor_val:
        if isinstance(sensor_val, list):
            sensors = [s.strip() for s in sensor_val]
        elif str(sensor_val).lower() != "all":
            sensors = [s.strip() for s in str(sensor_val).split(",")]

    extra_must, post_filters = module.build_extra_must(search_params)

    # Guard src/dest/any ip filters for modules that don't have the field in SOURCE_FIELDS —
    # a term query on a missing field returns zero results.
    has_src = "source.ip" in module.SOURCE_FIELDS
    has_dest = "destination.ip" in module.SOURCE_FIELDS
    src_ip_for_query = search_params.get("src_ip") if has_src else None
    dest_ip_for_query = search_params.get("dest_ip") if has_dest else None
    any_ip_for_query = search_params.get("any_ip") if (has_src or has_dest) else None

    has_src_port = "source.port" in module.SOURCE_FIELDS
    has_dest_port = "destination.port" in module.SOURCE_FIELDS
    has_proto = "network.transport" in module.SOURCE_FIELDS
    src_port_for_query = search_params.get("src_port") if has_src_port else None
    dest_port_for_query = search_params.get("dest_port") if has_dest_port else None
    proto_for_query = search_params.get("proto") if has_proto else None

    # Over-fetch when post-filters are active so truncation still yields enough rows.
    requested_limit = search_params.get("limit", 500)
    query_limit = (
        min(requested_limit * _OVERFETCH_MULTIPLIER, 5000) if post_filters else requested_limit
    )

    body, params = build_base_query(
        must_not=must_not,
        extra_must=extra_must,
        source_fields=module.SOURCE_FIELDS,
        limit=query_limit,
        time_range=search_params.get("time_range", "now-24h"),
        sensors=sensors,
        datasets=module.DATASETS,
        public_only=search_params.get("public_only", False),
        src_ip_filter=src_ip_for_query,
        dest_ip_filter=dest_ip_for_query,
        any_ip_filter=any_ip_for_query,
        direction=search_params.get("direction"),
        time_from=search_params.get("time_from"),
        time_to=search_params.get("time_to"),
        src_port_filter=src_port_for_query,
        dest_port_filter=dest_port_for_query,
        proto_filter=proto_for_query,
    )

    if search_params.get("profile"):
        body["profile"] = True

    # Cache is meaningless for profile runs (timing data is request-specific).
    use_cache = search_params.get("use_cache", False) and not search_params.get("profile")
    raw = None
    cache_key = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]
    cpath = _cache_path(cache_key)

    if use_cache:
        raw = _load_cache(cpath)
        if raw:
            console.print(f"[dim]Using cached response: {cpath}[/dim]")

    if raw is None:
        console.print(
            f"[dim]Querying OpenSearch / Malcolm"
            f" ({search_params.get('time_range', 'now-24h')})...[/dim]"
        )
        raw = query_opensearch(body, params)
        if use_cache:
            _save_cache(raw, cpath)

    if search_params.get("profile"):
        from src.querier.cli_loop import display_profile

        display_profile(raw)

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        console.print("[yellow]No records returned.[/yellow]")
        return []

    # Pre-parse hook — e.g. x509 community_id batch lookup, pe fuid→hash lookup.
    module.prepare_hits(hits)

    records = [module.parse_hit(hit.get("_source", {})) for hit in hits]
    records = [r for r in records if r]

    # Apply post-filters (over-fetch strategy: fetch 3× then truncate).
    if post_filters:
        keep = lambda r: all(pf(r) for pf in post_filters)  # noqa: E731
        records = [r for r in records if keep(r)]
        if len(records) < requested_limit:
            console.print(
                f"[dim]Showing {len(records)}/{requested_limit} after post-filtering — "
                f"increase time range for more results.[/dim]"
            )
        records = records[:requested_limit]

    return deduplicate_zeek(records, module.dedup_key)


async def run_query_async(module, search_params: dict) -> list:
    """Async variant of run_query — uses httpx.AsyncClient for the web fan-out path.

    Skips profile support (web path only).  The cache check, filter loading,
    query building, parsing, and deduplication are identical to the sync version.
    """
    if search_params.get("no_filters"):
        must_not: list = []
    else:
        must_not, _fcount, _errors = load_with_remap(FILTERS_DIR)

    sensors: list | None = None
    sensor_val = search_params.get("sensor", "all")
    if sensor_val:
        if isinstance(sensor_val, list):
            sensors = [s.strip() for s in sensor_val]
        elif str(sensor_val).lower() != "all":
            sensors = [s.strip() for s in str(sensor_val).split(",")]

    extra_must, post_filters = module.build_extra_must(search_params)

    has_src = "source.ip" in module.SOURCE_FIELDS
    has_dest = "destination.ip" in module.SOURCE_FIELDS
    src_ip_for_query = search_params.get("src_ip") if has_src else None
    dest_ip_for_query = search_params.get("dest_ip") if has_dest else None
    any_ip_for_query = search_params.get("any_ip") if (has_src or has_dest) else None

    has_src_port = "source.port" in module.SOURCE_FIELDS
    has_dest_port = "destination.port" in module.SOURCE_FIELDS
    has_proto = "network.transport" in module.SOURCE_FIELDS
    src_port_for_query = search_params.get("src_port") if has_src_port else None
    dest_port_for_query = search_params.get("dest_port") if has_dest_port else None
    proto_for_query = search_params.get("proto") if has_proto else None

    requested_limit = search_params.get("limit", 500)
    query_limit = (
        min(requested_limit * _OVERFETCH_MULTIPLIER, 5000) if post_filters else requested_limit
    )

    body, params = build_base_query(
        must_not=must_not,
        extra_must=extra_must,
        source_fields=module.SOURCE_FIELDS,
        limit=query_limit,
        time_range=search_params.get("time_range", "now-24h"),
        sensors=sensors,
        datasets=module.DATASETS,
        public_only=search_params.get("public_only", False),
        src_ip_filter=src_ip_for_query,
        dest_ip_filter=dest_ip_for_query,
        any_ip_filter=any_ip_for_query,
        direction=search_params.get("direction"),
        time_from=search_params.get("time_from"),
        time_to=search_params.get("time_to"),
        src_port_filter=src_port_for_query,
        dest_port_filter=dest_port_for_query,
        proto_filter=proto_for_query,
    )

    raw = await query_opensearch_async(body, params)

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        return []

    module.prepare_hits(hits)
    records = [module.parse_hit(hit.get("_source", {})) for hit in hits]
    records = [r for r in records if r]

    if post_filters:
        keep = lambda r: all(pf(r) for pf in post_filters)  # noqa: E731
        records = [r for r in records if keep(r)]
        records = records[:requested_limit]

    return deduplicate_zeek(records, module.dedup_key)
