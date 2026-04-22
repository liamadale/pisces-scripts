"""OpenSearch aggregation functions for the dashboard."""

from src.querier.zeek_modules.base import (
    FILTERS_DIR,
    build_base_query,
    load_with_remap,
    query_opensearch,
)


def agg_opensearch_protocols(time_range: str) -> dict:
    """Terms agg on event.dataset → top 10 by count."""
    must_not, _, _ = load_with_remap(FILTERS_DIR)
    body, params = build_base_query(
        must_not=must_not,
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=None,
        datasets=["all"],
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "protocols": {
            "terms": {
                "field": "event.dataset",
                "size": 10,
                "order": {"_count": "desc"},
            }
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("protocols", {}).get("buckets", []) if raw else []
    return {
        "labels": [b["key"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
    }


def agg_opensearch_sensors(time_range: str) -> dict:
    """Terms agg on host.name → sensor activity."""
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=None,
        datasets=["all"],
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "sensors": {
            "terms": {
                "field": "host.name",
                "size": 500,
                "order": {"_count": "desc"},
            }
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("sensors", {}).get("buckets", []) if raw else []
    return {
        "labels": [b["key"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
    }


def agg_opensearch_notice_count(time_range: str) -> int:
    """Total Zeek notice events in the given time range."""
    from src.querier.zeek_modules import MODULES

    mod = MODULES["notice"]
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=None,
        datasets=mod.DATASETS,
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    raw = query_opensearch(body, params)
    if not raw:
        return 0
    return raw.get("hits", {}).get("total", {}).get("value", 0)


def agg_opensearch_top_ips(time_range: str, limit: int = 15) -> dict:
    """Top source IPs by total cross-protocol frequency."""
    from apps.opensearch_web.queries import run_cross_protocol_query

    search_params = {
        "time_range": time_range,
        "sensor": "all",
        "limit": 500,
        "public_only": False,
        "src_ip": None,
        "direction": None,
        "no_filters": False,
        "use_cache": True,
    }
    rows = run_cross_protocol_query(search_params)
    top = rows[:limit]
    return {
        "ips": [r["src_ip"] for r in top],
        "counts": [r["total"] for r in top],
    }
