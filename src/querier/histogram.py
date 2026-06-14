#!/usr/bin/env python3
"""Date-histogram aggregation helper shared by the MCP tool and CLI renderer."""

from typing import Optional

from src.querier.builder import build_base_query
from src.querier.client import query_opensearch
from src.querier.runner import FILTERS_DIR, load_with_remap
from src.querier.zeek_modules import MODULES


def query_histogram(
    log_type: str,
    interval: str = "1h",
    time_range: str = "now-24h",
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    sensor: str | list[str] = "all",
    no_filters: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> list[dict]:
    """Run a date_histogram aggregation and return the time buckets.

    Returns a list of {key: epoch_ms, key_as_string: ISO-8601, doc_count: int}.
    An empty list is returned when OpenSearch is unreachable or returns no data.
    """
    if no_filters:
        must_not: list = []
    else:
        must_not, _, _ = load_with_remap(FILTERS_DIR)

    sensors: list | None = None
    if sensor:
        if isinstance(sensor, list):
            sensors = [s.strip() for s in sensor]
        elif str(sensor).lower() != "all":
            sensors = [s.strip() for s in str(sensor).split(",")]

    datasets: list[str]
    if log_type == "all" or log_type not in MODULES:
        datasets = ["all"]
    else:
        datasets = MODULES[log_type].DATASETS

    body, params = build_base_query(
        must_not=must_not,
        extra_must=[],
        source_fields=[],
        limit=0,
        time_range=time_range,
        sensors=sensors,
        datasets=datasets,
        src_ip_filter=src_ip,
        dest_ip_filter=dest_ip,
        time_from=time_from,
        time_to=time_to,
        sort=False,
    )
    body["size"] = 0
    body["track_total_hits"] = False
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
    if raw is None:
        return []

    buckets = raw.get("aggregations", {}).get("over_time", {}).get("buckets", [])
    return [
        {
            "key": b["key"],
            "key_as_string": b["key_as_string"],
            "doc_count": b["doc_count"],
        }
        for b in buckets
    ]
