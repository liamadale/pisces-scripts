"""Protocol-split dashboard panels using local OpenSearch/Zeek data.

Each function queries a specific Zeek log type and returns chart-ready dicts.
Field names match the Zeek module SOURCE_FIELDS exactly.
"""

import concurrent.futures

from src.querier.zeek_modules.base import build_base_query, query_opensearch


def _terms(field: str, time_range: str, datasets: list, size: int = 20) -> dict:
    """Run a terms aggregation; return {labels, counts}."""
    body, params = build_base_query(
        must_not=[], extra_must=[], source_fields=[], limit=0,
        time_range=time_range, sensors=None, datasets=datasets,
        public_only=False, src_ip_filter=None, direction=None, min_risk_score=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {"r": {"terms": {"field": field, "size": size, "order": {"_count": "desc"}}}}
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("r", {}).get("buckets", []) if raw else []
    return {"labels": [b["key"] for b in buckets], "counts": [b["doc_count"] for b in buckets]}


def _sum_terms(group_field: str, sum_field: str, time_range: str,
               datasets: list, size: int = 15) -> dict:
    """Terms agg with a nested sum sub-agg; return {labels, counts} sorted by sum desc."""
    body, params = build_base_query(
        must_not=[], extra_must=[], source_fields=[], limit=0,
        time_range=time_range, sensors=None, datasets=datasets,
        public_only=False, src_ip_filter=None, direction=None, min_risk_score=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "r": {
            "terms": {"field": group_field, "size": size},
            "aggs":  {"total": {"sum": {"field": sum_field}}},
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("r", {}).get("buckets", []) if raw else []
    buckets = sorted(buckets, key=lambda b: -b.get("total", {}).get("value", 0))
    return {
        "labels": [b["key"] for b in buckets],
        "counts": [int(b.get("total", {}).get("value", 0)) for b in buckets],
    }


# ---------------------------------------------------------------------------
# DNS panels
# ---------------------------------------------------------------------------

def panels_dns(time_range: str) -> dict:
    return {
        "query_types": _terms("zeek.dns.qtype_name",  time_range, ["dns"], size=12),
        "top_domains": _terms("zeek.dns.query",        time_range, ["dns"], size=25),
        "rcodes":      _terms("zeek.dns.rcode_name",   time_range, ["dns"], size=10),
    }


# ---------------------------------------------------------------------------
# HTTP panels
# ---------------------------------------------------------------------------

def panels_http(time_range: str) -> dict:
    return {
        "methods":       _terms("zeek.http.method",      time_range, ["http"], size=10),
        "status_codes":  _terms("zeek.http.status_code", time_range, ["http"], size=15),
        "top_hosts":     _terms("zeek.http.host",        time_range, ["http"], size=25),
        "top_useragents":_terms("zeek.http.user_agent",  time_range, ["http"], size=15),
    }


# ---------------------------------------------------------------------------
# SSL panels
# ---------------------------------------------------------------------------

def panels_ssl(time_range: str) -> dict:
    return {
        "versions":       _terms("zeek.ssl.version",           time_range, ["ssl"], size=10),
        "ciphers":        _terms("zeek.ssl.cipher",            time_range, ["ssl"], size=15),
        "top_sni":        _terms("zeek.ssl.server_name",       time_range, ["ssl"], size=25),
        "validation":     _terms("zeek.ssl.validation_status", time_range, ["ssl"], size=10),
    }


# ---------------------------------------------------------------------------
# Connection panels
# ---------------------------------------------------------------------------

def panels_conn(time_range: str) -> dict:
    return {
        "conn_states":  _terms("zeek.conn.conn_state",  time_range, ["conn"], size=15),
        "top_ports":    _terms("destination.port",       time_range, ["conn"], size=20),
        "bytes_orig":   _sum_terms("destination.port", "source.bytes",      time_range, ["conn"], size=15),
        "bytes_resp":   _sum_terms("destination.port", "destination.bytes", time_range, ["conn"], size=15),
    }


# ---------------------------------------------------------------------------
# Fetch all protocol panels in parallel
# ---------------------------------------------------------------------------

PROTOCOL_FETCHERS = {
    "dns":  panels_dns,
    "http": panels_http,
    "ssl":  panels_ssl,
    "conn": panels_conn,
}


def get_all_panels(time_range: str) -> dict:
    """Return {protocol: panels_dict} for all four protocols in parallel."""
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = {ex.submit(fn, time_range): proto for proto, fn in PROTOCOL_FETCHERS.items()}
        for future in concurrent.futures.as_completed(futures):
            proto = futures[future]
            try:
                results[proto] = future.result()
            except Exception as exc:
                results[proto] = {"error": str(exc)}
    return results
