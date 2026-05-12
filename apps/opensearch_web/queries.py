"""Web-layer query helpers — bridge between HTTP request params and run_query()."""

import asyncio
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from apps.opensearch_web import cache as wcache
from src.querier.runner import run_query_async
from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import (
    OpenSearchAuthError,
    OpenSearchConnectionError,
    console,
    run_query,
)

# Shared long-lived pool for all OpenSearch fan-out operations.  One pool
# bounds total thread count across all concurrent requests instead of letting
# each route spawn its own unlimited pool.
POOL = ThreadPoolExecutor(max_workers=min(32, (os.cpu_count() or 4) * 4))


def build_search_params_from_request(request, extra_keys=None) -> dict:
    """Build the search_params dict that run_query() expects, from an HTTP request."""
    params = {
        "time_range": request.values.get("time_range", "now-24h"),
        "time_from": request.values.get("from") or None,
        "time_to": request.values.get("to") or None,
        "sensor": request.values.get("sensor", "all"),
        "limit": int(v) if (v := request.values.get("limit", "").strip()) and v.isdigit() else 500,
        "public_only": request.values.get("public_only") in ("on", "true", "1"),
        "src_ip": request.values.get("src_ip") or None,
        "dest_ip": request.values.get("dest_ip") or None,
        "direction": request.values.get("direction") or None,
        "no_filters": False,
        "use_cache": False,
    }
    for key in extra_keys or []:
        params[key] = request.values.get(key) or None
    return params


def cached_run_query(log_type: str, search_params: dict) -> list:
    """run_query with in-memory TTL caching and single-flight dedup.

    If two concurrent requests arrive with the same params and both miss the
    cache, only one queries OpenSearch; the other waits and returns the same
    result.
    """
    cached = wcache.get(log_type, search_params)
    if cached is not None:
        return cached

    k = wcache.raw_key(log_type, search_params)
    event = wcache.claim(k)

    if event is None:
        wcache.wait_inflight(k)
        return wcache.get(log_type, search_params) or []

    try:
        records = run_query(MODULES[log_type], search_params)
        wcache.put(log_type, search_params, records)
        return records
    finally:
        wcache.release(k)


def run_cross_protocol_query(search_params: dict) -> list:
    """Query all IP-capable log types in parallel, aggregate by src_ip, sort by total freq.

    Modules with SUPPORTS_IP_FILTER=False (pe, capture_loss) are excluded — they have no
    src_ip to aggregate on.
    """
    ip_modules = {lt: mod for lt, mod in MODULES.items() if mod.SUPPORTS_IP_FILTER}
    results_by_type: dict = {}
    first_conn_error: Exception | None = None
    futures = {POOL.submit(cached_run_query, lt, search_params): lt for lt in ip_modules}
    for f in as_completed(futures):
        lt = futures[f]
        try:
            results_by_type[lt] = f.result()
        except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
            if first_conn_error is None:
                first_conn_error = exc
            results_by_type[lt] = []
        except Exception as exc:
            results_by_type[lt] = []
            console.print(f"[yellow]Cross-protocol query failed for {lt}: {exc}[/yellow]")

    if first_conn_error is not None:
        raise first_conn_error

    ip_data: dict = defaultdict(lambda: {"per_protocol": {lt: 0 for lt in ip_modules}, "total": 0})
    for lt, records in results_by_type.items():
        for rec in records:
            ip = rec.get("src_ip", "")
            if not ip or ip == "—":
                continue
            freq = rec.get("freq", 1)
            ip_data[ip]["per_protocol"][lt] += freq
            ip_data[ip]["total"] += freq

    return sorted(
        [{"src_ip": ip, **data} for ip, data in ip_data.items()],
        key=lambda x: -x["total"],
    )


async def cached_run_query_async(log_type: str, search_params: dict) -> list:
    """Async variant of cached_run_query — uses httpx.AsyncClient for web fan-out."""
    cached = wcache.get(log_type, search_params)
    if cached is not None:
        return cached

    k = wcache.raw_key(log_type, search_params)
    event = wcache.claim(k)

    if event is None:
        # Another coroutine is already fetching this — yield control until it's done.
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, wcache.wait_inflight, k)
        return wcache.get(log_type, search_params) or []

    try:
        records = await run_query_async(MODULES[log_type], search_params)
        wcache.put(log_type, search_params, records)
        return records
    finally:
        wcache.release(k)


async def run_cross_protocol_query_async(search_params: dict) -> list:
    """Async fan-out across all IP-capable log types using httpx.AsyncClient.

    Replaces the ThreadPoolExecutor-based run_cross_protocol_query with
    asyncio.gather, which avoids thread creation overhead and shares a single
    persistent HTTP/2-capable connection pool via httpx.AsyncClient.
    """
    ip_modules = {lt: mod for lt, mod in MODULES.items() if mod.SUPPORTS_IP_FILTER}
    first_conn_error: Exception | None = None

    tasks = {lt: cached_run_query_async(lt, search_params) for lt in ip_modules}
    task_results = await asyncio.gather(*tasks.values(), return_exceptions=True)

    results_by_type: dict = {}
    for lt, result in zip(tasks.keys(), task_results):
        if isinstance(result, (OpenSearchConnectionError, OpenSearchAuthError)):
            if first_conn_error is None:
                first_conn_error = result
            results_by_type[lt] = []
        elif isinstance(result, Exception):
            results_by_type[lt] = []
            console.print(f"[yellow]Cross-protocol query failed for {lt}: {result}[/yellow]")
        else:
            results_by_type[lt] = result

    if first_conn_error is not None:
        raise first_conn_error

    ip_data: dict = defaultdict(lambda: {"per_protocol": {lt: 0 for lt in ip_modules}, "total": 0})
    for lt, records in results_by_type.items():
        for rec in records:
            ip = rec.get("src_ip", "")
            if not ip or ip == "—":
                continue
            freq = rec.get("freq", 1)
            ip_data[ip]["per_protocol"][lt] += freq
            ip_data[ip]["total"] += freq

    return sorted(
        [{"src_ip": ip, **data} for ip, data in ip_data.items()],
        key=lambda x: -x["total"],
    )
