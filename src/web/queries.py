"""Web-layer query helpers — bridge between HTTP request params and run_query()."""

from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import run_query
from src.web import cache as wcache

# Protocol-specific search_params keys forwarded from HTTP request
MODULE_PARAM_KEYS: dict = {
    "conn":   [],
    "dns":    ["dns_query", "rcode", "qtype"],
    "http":   ["http_method", "http_host", "http_uri", "status_code"],
    "ssl":    ["ssl_sni", "ssl_invalid_only"],
    "smtp":   ["smtp_mail_from", "smtp_rcpt_to", "smtp_subject"],
    "rdp":    ["rdp_result", "rdp_cookie"],
    "smb":    ["smb_share", "smb_action"],
    "ssh":    ["ssh_failed_only", "ssh_auth_result"],
    "notice": ["notice_note"],
    "weird":  ["weird_name"],
}


def build_search_params_from_request(request, extra_keys=None) -> dict:
    """Build the search_params dict that run_query() expects, from an HTTP request."""
    params = {
        "time_range":  request.values.get("time_range", "now-24h"),
        "sensor":      request.values.get("sensor", "all"),
        "limit":       int(v) if (v := request.values.get("limit", "").strip()) and v.isdigit() else 500,
        "public_only": request.values.get("public_only") in ("on", "true", "1"),
        "src_ip":          request.values.get("src_ip") or None,
        "direction":       request.values.get("direction") or None,
        "min_risk_score":  int(v) if (v := request.values.get("min_risk", "").strip()) else None,
        "no_filters":      False,
        "use_cache":       False,
    }
    for key in (extra_keys or []):
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
    """Query all log types in parallel, aggregate by src_ip, sort by total freq."""
    results_by_type: dict = {}
    with ThreadPoolExecutor(max_workers=len(MODULES)) as ex:
        futures = {ex.submit(cached_run_query, lt, search_params): lt for lt in MODULES}
        for f in as_completed(futures):
            lt = futures[f]
            try:
                results_by_type[lt] = f.result()
            except Exception:
                results_by_type[lt] = []

    ip_data: dict = defaultdict(lambda: {"per_protocol": {lt: 0 for lt in MODULES}, "total": 0})
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

