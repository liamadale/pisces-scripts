"""Web-layer query helpers — bridge between HTTP request params and kibana_module."""

from src.querier.kibana_module import (
    KibanaModule,
    run_kibana_query,
    get_ip_severity_overview,
)
from apps.kibana_web import cache as wcache

_module = KibanaModule()


def build_search_params_from_request(request) -> dict:
    """Map HTTP request values to the search_params dict kibana_module expects."""
    severity_raw = request.values.get("severity", "").strip()
    try:
        severity = max(1, min(3, int(severity_raw)))
    except (ValueError, TypeError):
        severity = 3

    limit_raw = request.values.get("limit", "").strip()
    limit = int(limit_raw) if limit_raw.isdigit() else 500

    return {
        "time_range": request.values.get("time_range", "now-24h"),
        "severity": severity,
        "cities": request.values.get("cities", "all") or "all",
        "src_ip": request.values.get("src_ip") or None,
        "signature": request.values.get("signature") or None,
        "protocol": request.values.get("protocol") or None,
        "min_bytes": int(v)
        if (v := request.values.get("min_bytes", "").strip()) and v.isdigit()
        else None,
        "public_only": request.values.get("public_only") in ("on", "true", "1"),
        "limit": limit,
        "no_filters": False,
        "use_cache": False,
    }


def cached_run_alerts(search_params: dict) -> list:
    """run_kibana_query with TTL caching."""
    cached = wcache.get("alerts", search_params)
    if cached is not None:
        return cached
    records = run_kibana_query(_module, search_params)
    wcache.put("alerts", search_params, records)
    return records


def cached_run_overview(search_params: dict) -> list:
    """get_ip_severity_overview with TTL caching."""
    cached = wcache.get("overview", search_params)
    if cached is not None:
        return cached
    rows = get_ip_severity_overview(search_params)
    wcache.put("overview", search_params, rows)
    return rows
