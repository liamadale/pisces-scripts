"""Kibana aggregation functions for the dashboard."""

from src.querier.kibana_module import (
    get_signature_frequency,
    get_cities_data,
    get_ip_severity_overview,
)


def agg_kibana_severity(time_range: str) -> dict:
    """Sum of sev1/sev2/sev3 across all IPs."""
    rows = get_ip_severity_overview({"time_range": time_range, "no_filters": False})
    return {
        "sev1": sum(r["sev1"] for r in rows),
        "sev2": sum(r["sev2"] for r in rows),
        "sev3": sum(r["sev3"] for r in rows),
    }


def agg_kibana_signatures(time_range: str) -> dict:
    """Top 20 Suricata signatures by alert count."""
    buckets = get_signature_frequency({"time_range": time_range, "no_filters": False, "severity": 3})
    # get_signature_frequency returns asc (rarest first) — reverse for top-N
    top = sorted(buckets, key=lambda b: -b["doc_count"])[:20]
    return {
        "labels": [b["key"] for b in top],
        "counts": [b["doc_count"] for b in top],
    }


def agg_kibana_cities(time_range: str) -> dict:
    """Alert counts by city/clientID."""
    buckets = get_cities_data(time_range)
    return {
        "labels": [b["key"] for b in buckets],
        "counts": [b["doc_count"] for b in buckets],
    }
