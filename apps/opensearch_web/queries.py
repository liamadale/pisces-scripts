"""Web-layer query helpers — bridge between HTTP request params and run_query()."""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from apps.opensearch_web import cache as wcache
from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import run_query


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
    """run_query with in-memory TTL caching. Falls through to OpenSearch on miss."""
    cached = wcache.get(log_type, search_params)
    if cached is not None:
        return cached
    records = run_query(MODULES[log_type], search_params)
    wcache.put(log_type, search_params, records)
    return records


def run_cross_protocol_query(search_params: dict) -> list:
    """Query all IP-capable log types in parallel, aggregate by src_ip, sort by total freq.

    Modules with SUPPORTS_IP_FILTER=False (pe, capture_loss) are excluded — they have no
    src_ip to aggregate on.
    """
    ip_modules = {lt: mod for lt, mod in MODULES.items() if mod.SUPPORTS_IP_FILTER}
    results_by_type: dict = {}
    with ThreadPoolExecutor(max_workers=len(ip_modules)) as ex:
        futures = {ex.submit(cached_run_query, lt, search_params): lt for lt in ip_modules}
        for f in as_completed(futures):
            lt = futures[f]
            try:
                results_by_type[lt] = f.result()
            except Exception:
                results_by_type[lt] = []

    ip_data: dict = defaultdict(lambda: {"per_protocol": {lt: 0 for lt in ip_modules}, "total": 0})
    for lt, records in results_by_type.items():
        for rec in records:
            ip = rec.get("src_ip", "")
            if not ip:
                continue
            freq = rec.get("freq", 1)
            ip_data[ip]["per_protocol"][lt] += freq
            ip_data[ip]["total"] += freq

    return sorted(
        [{"src_ip": ip, **data} for ip, data in ip_data.items()],
        key=lambda x: -x["total"],
    )
