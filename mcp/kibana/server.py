#!/usr/bin/env python3
"""Kibana MCP Server — thin adapter over the Kibana/Suricata backend.

4 tools: search_alerts, list_cities, get_signature_summary, raw_kibana_search.

Run locally (MCP Inspector):
    source .venv/bin/activate && pip install mcp[cli]
    PISCES_USERNAME=x PISCES_PASSWORD=y mcp dev mcp/kibana/server.py

Run via Docker:
    docker build -f mcp/kibana/Dockerfile -t kibana-mcp .
    docker run --rm -i -e PISCES_USERNAME -e PISCES_PASSWORD kibana-mcp
"""

import json
import sys
import os
from typing import Optional

# Allow importing project modules when run from the mcp/kibana/ directory or as a
# Docker container with WORKDIR /app.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dotenv import load_dotenv

# Load credentials before any project import that checks env vars.
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(os.path.abspath(_env_path))

from src.utils.dns import setup_dns
setup_dns()

from mcp.server.fastmcp import FastMCP
from src.querier.kibana_module import KibanaModule, run_kibana_query, query_kibana, INDEX

mcp = FastMCP("kibana")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialise_alerts(alerts: list) -> list:
    """Strip _raw keys and convert sets/lists of cities to sorted lists."""
    out = []
    for alert in alerts:
        a = {k: v for k, v in alert.items() if k != "_raw"}
        if isinstance(a.get("cities"), set):
            a["cities"] = sorted(a["cities"])
        out.append(a)
    return out


def _ok(data) -> str:
    return json.dumps({"status": "ok", "data": data}, default=str)


def _err(msg: str) -> str:
    return json.dumps({"status": "error", "message": msg})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def search_alerts(
    time_range: str = "now-24h",
    severity: int = 3,
    cities: str = "all",
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    signature: Optional[str] = None,
    min_bytes: Optional[int] = None,
    protocol: Optional[str] = None,
    limit: int = 200,
    public_only: bool = False,
    no_filters: bool = False,
) -> str:
    """Search Suricata IDS alerts via Kibana/ELK.

    Args:
        time_range: Elasticsearch date math time range, e.g. "now-24h", "now-7d".
        severity: Maximum Suricata severity level to include (1=critical, 2=high, 3=low).
        cities: Comma-separated list of clientID values to filter by, or "all".
        src_ip: Post-filter by source IP address.
        dest_ip: Post-filter by destination IP address.
        signature: Suricata rule signature substring to match, e.g. "ET SCAN".
        min_bytes: Minimum bytes transferred to server.
        protocol: Application protocol to filter by, e.g. "http", "tls".
        limit: Maximum number of raw events to retrieve before deduplication.
        public_only: If True, exclude RFC-1918 private source IPs.
        no_filters: If True, disable all false-positive YAML filters.
    """
    try:
        params: dict = {
            "time_range": time_range,
            "severity": severity,
            "cities": cities,
            "limit": limit,
            "public_only": public_only,
            "no_filters": no_filters,
        }
        if signature:
            params["signature"] = signature
        if min_bytes is not None:
            params["min_bytes"] = min_bytes
        if protocol:
            params["protocol"] = protocol

        alerts = run_kibana_query(KibanaModule(), params)

        if src_ip:
            alerts = [a for a in alerts if a.get("src_ip") == src_ip]
        if dest_ip:
            alerts = [a for a in alerts if a.get("dest_ip") == dest_ip]

        return _ok({"count": len(alerts), "alerts": _serialise_alerts(alerts)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def list_cities(time_range: str = "now-7d") -> str:
    """List all cities (clientID values) that have sent Suricata alerts in the given window.

    Returns city names and their alert counts, sorted by volume.
    City values can be passed to search_alerts' 'cities' parameter to scope queries.

    Args:
        time_range: Elasticsearch date math time range, e.g. "now-7d", "now-30d".
    """
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
                    ]
                }
            },
            "aggs": {
                "cities": {
                    "terms": {
                        "field": "clientID",
                        "size": 500,
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_kibana(body, params)
        if raw is None:
            return _err("Kibana query failed — check credentials")
        buckets = raw.get("aggregations", {}).get("cities", {}).get("buckets", [])
        cities = [{"name": b["key"], "alert_count": b["doc_count"]} for b in buckets]
        return _ok({"time_range": time_range, "cities": cities})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def get_signature_summary(
    time_range: str = "now-24h",
    severity: int = 3,
    limit: int = 50,
) -> str:
    """Aggregate Suricata alert signatures by frequency over the given time window.

    Useful for a quick overview of what rules are firing without fetching full records.

    Args:
        time_range: Elasticsearch date math time range, e.g. "now-24h", "now-7d".
        severity: Maximum Suricata severity level to include (1=critical, 2=high, 3=low).
        limit: Maximum number of top signatures to return.
    """
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                        {"range": {"alert.severity": {"lte": severity}}},
                    ]
                }
            },
            "aggs": {
                "signatures": {
                    "terms": {
                        "field": "alert.signature",
                        "size": limit,
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_kibana(body, params)
        if raw is None:
            return _err("Kibana query failed — check credentials")
        buckets = (
            raw.get("aggregations", {})
            .get("signatures", {})
            .get("buckets", [])
        )
        signatures = [{"signature": b["key"], "count": b["doc_count"]} for b in buckets]
        return _ok({"time_range": time_range, "signatures": signatures})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def raw_kibana_search(
    query_body: str,
    index_path: str = f"{INDEX}/_search",
) -> str:
    """Send a raw Elasticsearch DSL query body directly to Kibana.

    Use this escape hatch for advanced aggregations or any field access not
    covered by the other tools.

    Args:
        query_body: JSON string containing the full ES query body (e.g. size, query, aggs).
        index_path: Index path portion of the URL, default "suricata*/_search".

    Example:
        query_body = '{"size": 1, "query": {"match_all": {}}}'
    """
    try:
        try:
            body = json.loads(query_body)
        except json.JSONDecodeError as exc:
            return _err(f"Invalid JSON in query_body: {exc}")

        params = {"path": index_path, "method": "POST"}
        raw = query_kibana(body, params)
        if raw is None:
            return _err("Kibana query failed — check credentials")
        return _ok(raw)
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
