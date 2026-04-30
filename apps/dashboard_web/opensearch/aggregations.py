"""OpenSearch aggregation functions for the dashboard."""

from src.querier.zeek_modules.base import (
    FILTERS_DIR,
    build_base_query,
    load_with_remap,
    query_opensearch,
)


def parse_sensors(raw: str) -> list | None:
    """Parse a comma-separated sensor string into a list, or None for 'all'."""
    if not raw or raw.strip().lower() == "all":
        return None
    return [s.strip() for s in raw.split(",") if s.strip()]


def _interval_for_range(time_range: str) -> str:
    """Pick a sensible date_histogram interval for the given time range."""
    short = time_range.replace("now-", "")
    if short in ("1h", "3h", "6h"):
        return "10m"
    if short in ("12h", "24h"):
        return "1h"
    if short in ("2d", "3d"):
        return "3h"
    return "1d"


def agg_opensearch_sensors(time_range: str) -> dict:
    """Terms agg on host.name → sensor activity. Always queries all sensors."""
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


def agg_opensearch_notice_count(time_range: str, sensors: list | None = None) -> int:
    """Total Zeek notice events in the given time range."""
    from src.querier.zeek_modules import MODULES

    mod = MODULES["notice"]
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
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


def agg_opensearch_top_ips(time_range: str, sensors: list | None = None, limit: int = 15) -> dict:
    """Top source IPs by total cross-protocol frequency."""
    from apps.opensearch_web.queries import run_cross_protocol_query

    sensor_str = ",".join(sensors) if sensors else "all"
    search_params = {
        "time_range": time_range,
        "sensor": sensor_str,
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


def agg_suricata_alert_count(time_range: str, sensors: list | None = None) -> int:
    """Total Suricata alert events (excluding STREAM noise) in the given time range."""
    body, params = build_base_query(
        must_not=[{"wildcard": {"rule.name": "SURICATA STREAM*"}}],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
        datasets=["alert"],
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


def agg_suricata_over_time(time_range: str, sensors: list | None = None) -> dict:
    """Suricata alert count (excluding STREAM noise) as a date_histogram."""
    interval = _interval_for_range(time_range)
    body, params = build_base_query(
        must_not=[{"wildcard": {"rule.name": "SURICATA STREAM*"}}],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
        datasets=["alert"],
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "over_time": {
            "date_histogram": {
                "field": "@timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
            }
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", []) if raw else []
    return {
        "timestamps": [b["key_as_string"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
        "interval": interval,
    }


def agg_notice_over_time(time_range: str, sensors: list | None = None) -> dict:
    """Notice count as a date_histogram for the given time range."""
    from src.querier.zeek_modules import MODULES

    mod = MODULES["notice"]
    interval = _interval_for_range(time_range)
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
        datasets=mod.DATASETS,
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "over_time": {
            "date_histogram": {
                "field": "@timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
            }
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", []) if raw else []
    return {
        "timestamps": [b["key_as_string"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
        "interval": interval,
    }


def agg_conn_volume_over_time(time_range: str, sensors: list | None = None) -> dict:
    """Connection volume as a date_histogram for the given time range."""
    interval = _interval_for_range(time_range)
    body, params = build_base_query(
        must_not=[],
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
        datasets=["conn"],
        public_only=False,
        src_ip_filter=None,
        direction=None,
    )
    body["size"] = 0
    body.pop("sort", None)
    body.pop("_source", None)
    body["aggs"] = {
        "over_time": {
            "date_histogram": {
                "field": "@timestamp",
                "fixed_interval": interval,
                "min_doc_count": 0,
            }
        }
    }
    raw = query_opensearch(body, params)
    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", []) if raw else []
    return {
        "timestamps": [b["key_as_string"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
        "interval": interval,
    }


def agg_new_ips_delta(time_range: str, sensors: list | None = None) -> dict:
    """Compare unique source IPs in the current window vs the previous window.

    Returns {current, previous, delta, pct_change} where delta = current - previous.
    """
    must_not, _, _ = load_with_remap(FILTERS_DIR)

    def _unique_count(tr: str) -> int:
        body, params = build_base_query(
            must_not=must_not,
            extra_must=[],
            source_fields=[],
            limit=0,
            time_range=tr,
            sensors=sensors,
            datasets=["all"],
            public_only=True,
            src_ip_filter=None,
            direction=None,
        )
        body["size"] = 0
        body.pop("sort", None)
        body.pop("_source", None)
        body["aggs"] = {
            "uniq": {"cardinality": {"field": "source.ip", "precision_threshold": 3000}}
        }
        raw = query_opensearch(body, params)
        if not raw:
            return 0
        return raw.get("aggregations", {}).get("uniq", {}).get("value", 0)

    # Map current range to a "previous" range of the same width
    short = time_range.replace("now-", "")
    prev_map = {
        "1h": "now-2h",
        "6h": "now-12h",
        "12h": "now-24h",
        "24h": "now-2d",
        "2d": "now-4d",
        "7d": "now-14d",
        "14d": "now-28d",
        "30d": "now-60d",
    }
    prev_range = prev_map.get(short, "now-2d")

    current = _unique_count(time_range)
    previous = _unique_count(prev_range)
    delta = current - previous
    pct = round((delta / previous) * 100, 1) if previous else 0.0
    return {
        "current": current,
        "previous": previous,
        "delta": delta,
        "pct_change": pct,
    }
