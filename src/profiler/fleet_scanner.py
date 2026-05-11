#!/usr/bin/env python3
"""Fleet scanner — JA4 clustering for device discovery across a sensor.

Runs a single aggregation query to collect per-IP JA4 fingerprint sets,
filters to private IPs, then clusters devices by Jaccard similarity.

Usage:
    uv run src/profiler/fleet_scanner.py --sensor <sensor-hostname>
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.zeek_modules.base import (
    INDEX,
    OpenSearchAuthError,
    OpenSearchConnectionError,
    is_private,
    query_opensearch,
)

_PARAMS = {"path": f"{INDEX}/_search", "method": "POST"}

JACCARD_THRESHOLD = 0.7


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class DeviceCluster:
    """A group of IPs sharing similar JA4 fingerprint sets."""

    ja4_set: set[str]
    ips: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Jaccard similarity
# ---------------------------------------------------------------------------


def jaccard(a: set, b: set) -> float:
    """Jaccard similarity coefficient: |A ∩ B| / |A ∪ B|."""
    if not a and not b:
        return 1.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


def cluster_by_similarity(
    ip_sets: dict[str, set[str]],
    threshold: float = JACCARD_THRESHOLD,
) -> list[DeviceCluster]:
    """Group IPs into clusters by Jaccard similarity on fingerprint sets.

    Single-pass greedy: for each IP, find the first cluster with similarity
    >= threshold and add it. If none match, start a new cluster.
    """
    clusters: list[DeviceCluster] = []
    for ip, fp_set in ip_sets.items():
        merged = False
        for cluster in clusters:
            if jaccard(fp_set, cluster.ja4_set) >= threshold:
                cluster.ips.append(ip)
                cluster.ja4_set = cluster.ja4_set | fp_set
                merged = True
                break
        if not merged:
            clusters.append(DeviceCluster(ja4_set=set(fp_set), ips=[ip]))

    return sorted(clusters, key=lambda c: -len(c.ips))


# ---------------------------------------------------------------------------
# Fleet query
# ---------------------------------------------------------------------------


def _fleet_ja4_query(sensor: str, time_range: str) -> dict:
    """Single aggregation: per-IP JA4 sets across the sensor."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "ssl"}},
                    {"term": {"host.name": sensor}},
                ]
            }
        },
        "aggs": {
            "per_ip": {
                "terms": {"field": "source.ip", "size": 1000},
                "aggs": {
                    "ja4_set": {"terms": {"field": "tls.ja4", "size": 10}},
                },
            }
        },
    }


def scan_fleet(
    sensor: str,
    *,
    time_range: str = "now-7d",
    threshold: float = JACCARD_THRESHOLD,
) -> list[DeviceCluster]:
    """Scan a sensor's fleet and cluster private IPs by JA4 similarity.

    Args:
        sensor: Sensor hostname (required).
        time_range: ES date-math range (default: now-7d).
        threshold: Jaccard similarity threshold (default: 0.7).

    Returns:
        List of DeviceClusters sorted by size descending.
    """
    try:
        raw = query_opensearch(_fleet_ja4_query(sensor, time_range), _PARAMS)
    except (OpenSearchConnectionError, OpenSearchAuthError):
        return []

    buckets = raw.get("aggregations", {}).get("per_ip", {}).get("buckets", [])

    # Post-filter to private IPs and extract top-5 JA4 hashes per IP
    ip_sets: dict[str, set[str]] = {}
    for bucket in buckets:
        ip = bucket["key"]
        if not is_private(ip):
            continue
        ja4_hashes = {b["key"] for b in bucket.get("ja4_set", {}).get("buckets", [])[:5]}
        if ja4_hashes:
            ip_sets[ip] = ja4_hashes

    return cluster_by_similarity(ip_sets, threshold)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _display_clusters(clusters: list[DeviceCluster], sensor: str) -> None:
    """Render fleet clusters as a Rich table."""
    from rich import box
    from rich.console import Console
    from rich.table import Table

    console = Console()

    total_ips = sum(len(c.ips) for c in clusters)
    console.print(
        f"\n[bold]Fleet Scan:[/bold] {sensor}  "
        f"[dim]{total_ips} private IPs → {len(clusters)} cluster(s)[/dim]"
    )

    t = Table(box=box.SIMPLE_HEAVY, expand=False)
    t.add_column("#", style="dim", width=3)
    t.add_column("Size", justify="right")
    t.add_column("JA4 Fingerprints")
    t.add_column("Sample IPs")

    for idx, cluster in enumerate(clusters, 1):
        ja4_str = ", ".join(sorted(cluster.ja4_set)[:3])
        if len(cluster.ja4_set) > 3:
            ja4_str += f" (+{len(cluster.ja4_set) - 3})"
        ip_str = ", ".join(cluster.ips[:5])
        if len(cluster.ips) > 5:
            ip_str += f" (+{len(cluster.ips) - 5})"
        t.add_row(str(idx), str(len(cluster.ips)), ja4_str, ip_str)

    console.print(t)


def main() -> None:
    """CLI entry point for fleet scanner."""
    load_dotenv()

    from src.utils.dns import setup_dns

    setup_dns()

    parser = argparse.ArgumentParser(
        description="PISCES Fleet Scanner — JA4 clustering for device discovery"
    )
    parser.add_argument("--sensor", required=True, help="Sensor hostname (required)")
    parser.add_argument(
        "--time-range", default="now-7d", help="ES date-math range (default: now-7d)"
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=JACCARD_THRESHOLD,
        help=f"Jaccard similarity threshold (default: {JACCARD_THRESHOLD})",
    )
    args = parser.parse_args()

    clusters = scan_fleet(args.sensor, time_range=args.time_range, threshold=args.threshold)
    if clusters:
        _display_clusters(clusters, args.sensor)
    else:
        from rich.console import Console

        Console().print("[yellow]No private IPs with TLS traffic found.[/yellow]")


if __name__ == "__main__":
    main()
