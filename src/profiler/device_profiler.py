#!/usr/bin/env python3
"""Device profiler — Phase 1a: conn-based device profiling for private IPs.

Runs two parallel aggregation queries (conn-outbound and conn-inbound) against
OpenSearch to build a minimal DeviceProfile for a single private IP on a
specific sensor.

Usage:
    uv run src/profiler/device_profiler.py --ip <private-ip> --sensor <sensor-hostname>
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.zeek_modules.base import (
    INDEX,
    is_private,
    query_opensearch,
)

_PARAMS = {"path": f"{INDEX}/_search", "method": "POST"}


# ---------------------------------------------------------------------------
# DeviceProfile dataclass (Phase 1a — conn fields only)
# ---------------------------------------------------------------------------


@dataclass
class DeviceProfile:
    """Minimal device profile built from conn-outbound and conn-inbound."""

    ip: str
    sensor: str
    time_range: str

    # Outbound (device as client)
    dest_port_distribution: dict[int, int] = field(default_factory=dict)
    protocol_mix: dict[str, int] = field(default_factory=dict)
    unique_dest_count: int = 0
    bytes_sent: int = 0
    ja4t_fingerprints: list[dict] = field(default_factory=list)

    # Inbound (device as server)
    inbound_services: list[dict] = field(default_factory=list)
    inbound_client_count: int = 0
    bytes_received: int = 0

    # Timestamps
    first_seen: str = ""
    last_seen: str = ""


# ---------------------------------------------------------------------------
# Aggregation queries
# ---------------------------------------------------------------------------


def _conn_outbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Build conn-outbound aggregation body (device as source)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "conn"}},
                    {"term": {"source.ip": ip}},
                    {"term": {"host.name": sensor}},
                ]
            }
        },
        "aggs": {
            "dest_ports": {"terms": {"field": "destination.port", "size": 10}},
            "app_protos": {"terms": {"field": "network.application", "size": 10}},
            "unique_dests": {"cardinality": {"field": "destination.ip"}},
            "total_bytes": {"sum": {"field": "source.bytes"}},
            "ja4t_fingerprints": {"terms": {"field": "zeek.conn.ja4t", "size": 5}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


def _conn_inbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Build conn-inbound aggregation body (device as destination)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "conn"}},
                    {"term": {"destination.ip": ip}},
                    {"term": {"host.name": sensor}},
                ]
            }
        },
        "aggs": {
            "inbound_ports": {
                "terms": {"field": "destination.port", "size": 20},
                "aggs": {"app_proto": {"terms": {"field": "network.application", "size": 1}}},
            },
            "unique_clients": {"cardinality": {"field": "source.ip"}},
            "total_bytes": {"sum": {"field": "destination.bytes"}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def _parse_outbound(aggs: dict) -> dict:
    """Extract outbound fields from aggregation response."""
    dest_ports = {
        int(b["key"]): b["doc_count"] for b in aggs.get("dest_ports", {}).get("buckets", [])
    }
    app_protos = {b["key"]: b["doc_count"] for b in aggs.get("app_protos", {}).get("buckets", [])}
    ja4t = [
        {"hash": b["key"], "count": b["doc_count"]}
        for b in aggs.get("ja4t_fingerprints", {}).get("buckets", [])
    ]
    ts = aggs.get("time_range", {})
    return {
        "dest_port_distribution": dest_ports,
        "protocol_mix": app_protos,
        "unique_dest_count": int(aggs.get("unique_dests", {}).get("value", 0)),
        "bytes_sent": int(aggs.get("total_bytes", {}).get("value", 0)),
        "ja4t_fingerprints": ja4t,
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


def _parse_inbound(aggs: dict) -> dict:
    """Extract inbound fields from aggregation response."""
    services = []
    for b in aggs.get("inbound_ports", {}).get("buckets", []):
        proto_buckets = b.get("app_proto", {}).get("buckets", [])
        app_proto = proto_buckets[0]["key"] if proto_buckets else ""
        services.append({"port": int(b["key"]), "app_proto": app_proto, "count": b["doc_count"]})
    ts = aggs.get("time_range", {})
    return {
        "inbound_services": services,
        "inbound_client_count": int(aggs.get("unique_clients", {}).get("value", 0)),
        "bytes_received": int(aggs.get("total_bytes", {}).get("value", 0)),
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def profile_device(
    ip: str,
    *,
    time_range: str = "now-7d",
    sensor: str = "all",
) -> DeviceProfile:
    """Profile a private IP using conn-outbound and conn-inbound aggregations.

    Args:
        ip: Private IP address to profile.
        time_range: Elasticsearch date-math range (default: now-7d).
        sensor: Sensor hostname (required — private IPs overlap across sensors).

    Returns:
        DeviceProfile with conn-derived fields populated.

    Raises:
        ValueError: If the IP is not a private/RFC-1918 address.
    """
    if not is_private(ip):
        raise ValueError(f"{ip} is not a private IP — use enrich_ip() for public IPs")

    queries = {
        "outbound": _conn_outbound_query(ip, time_range, sensor),
        "inbound": _conn_inbound_query(ip, time_range, sensor),
    }

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=2) as ex:
        futures = {
            ex.submit(query_opensearch, body, _PARAMS): name for name, body in queries.items()
        }
        for f in as_completed(futures):
            name = futures[f]
            raw = f.result()
            aggs = raw.get("aggregations", {}) if raw else {}
            results[name] = aggs

    out = _parse_outbound(results.get("outbound", {}))
    inb = _parse_inbound(results.get("inbound", {}))

    # Merge timestamps — take the earliest first_seen and latest last_seen.
    first_seen = min((t for t in [out["first_seen"], inb["first_seen"]] if t), default="")
    last_seen = max((t for t in [out["last_seen"], inb["last_seen"]] if t), default="")

    return DeviceProfile(
        ip=ip,
        sensor=sensor,
        time_range=time_range,
        dest_port_distribution=out["dest_port_distribution"],
        protocol_mix=out["protocol_mix"],
        unique_dest_count=out["unique_dest_count"],
        bytes_sent=out["bytes_sent"],
        ja4t_fingerprints=out["ja4t_fingerprints"],
        inbound_services=inb["inbound_services"],
        inbound_client_count=inb["inbound_client_count"],
        bytes_received=inb["bytes_received"],
        first_seen=first_seen,
        last_seen=last_seen,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _display_profile(profile: DeviceProfile) -> None:
    """Render a DeviceProfile as Rich tables."""
    from rich import box
    from rich.console import Console
    from rich.table import Table

    from src.utils.format import fmt_bytes

    console = Console()

    console.print(
        f"\n[bold]Device Profile:[/bold] {profile.ip}"
        f"  [dim]sensor={profile.sensor}  range={profile.time_range}[/dim]"
    )
    if profile.first_seen:
        console.print(
            f"[dim]First seen: {profile.first_seen[:19]}  Last seen: {profile.last_seen[:19]}[/dim]"
        )

    # Inbound services
    if profile.inbound_services:
        t = Table(
            title="Inbound Services (device as server)",
            box=box.SIMPLE_HEAVY,
            expand=False,
        )
        t.add_column("Port", justify="right")
        t.add_column("Protocol")
        t.add_column("Count", justify="right")
        for svc in profile.inbound_services:
            t.add_row(str(svc["port"]), svc["app_proto"] or "—", str(svc["count"]))
        console.print(t)
    else:
        console.print("[dim]No inbound services detected.[/dim]")

    console.print(
        f"[dim]Unique inbound clients: {profile.inbound_client_count}  "
        f"Bytes received: {fmt_bytes(profile.bytes_received)}[/dim]"
    )

    # Outbound summary
    if profile.protocol_mix:
        t = Table(
            title="Outbound Protocol Mix (device as client)",
            box=box.SIMPLE_HEAVY,
            expand=False,
        )
        t.add_column("App Protocol")
        t.add_column("Count", justify="right")
        for proto, count in sorted(profile.protocol_mix.items(), key=lambda x: -x[1]):
            t.add_row(proto, str(count))
        console.print(t)

    if profile.dest_port_distribution:
        t = Table(
            title="Top Destination Ports",
            box=box.SIMPLE_HEAVY,
            expand=False,
        )
        t.add_column("Port", justify="right")
        t.add_column("Count", justify="right")
        for port, count in sorted(profile.dest_port_distribution.items(), key=lambda x: -x[1]):
            t.add_row(str(port), str(count))
        console.print(t)

    console.print(
        f"[dim]Unique destinations: {profile.unique_dest_count}  "
        f"Bytes sent: {fmt_bytes(profile.bytes_sent)}[/dim]"
    )

    # JA4T fingerprints
    if profile.ja4t_fingerprints:
        t = Table(
            title="JA4T TCP Fingerprints",
            box=box.SIMPLE_HEAVY,
            expand=False,
        )
        t.add_column("Hash")
        t.add_column("Count", justify="right")
        for fp in profile.ja4t_fingerprints:
            t.add_row(fp["hash"], str(fp["count"]))
        console.print(t)


def main() -> None:
    """CLI entry point for device profiler."""
    load_dotenv()

    from src.utils.dns import setup_dns

    setup_dns()

    parser = argparse.ArgumentParser(
        description="PISCES Device Profiler — private IP fingerprinting via Zeek conn logs"
    )
    parser.add_argument("--ip", required=True, help="Private IP to profile")
    parser.add_argument(
        "--sensor",
        required=True,
        help="Sensor hostname (required — private IPs overlap across sensors)",
    )
    parser.add_argument(
        "--time-range", default="now-7d", help="ES date-math range (default: now-7d)"
    )
    args = parser.parse_args()

    profile = profile_device(args.ip, time_range=args.time_range, sensor=args.sensor)
    _display_profile(profile)


if __name__ == "__main__":
    main()
