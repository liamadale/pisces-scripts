#!/usr/bin/env python3
"""Zeek tunnel log module — protocol tunneling / covert channel detection."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class TunnelModule(ZeekModule):
    DATASETS = ["tunnel"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "destination.ip",
        "zeek.tunnel.tunnel_type",
        "zeek.tunnel.action",
        "network.community_id",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    WEB_CATEGORY = "remote"
    WEB_COLUMNS = [
        ("Tunnel Type", lambda r: r.get("tunnel_type", "—") or "—"),
        ("Action", lambda r: r.get("action", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Tunnel Type", lambda r: r.get("tunnel_type", "—")),
        ("Action", lambda r: r.get("action", "—")),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zt = src.get("zeek", {}).get("tunnel", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "tunnel_type": zt.get("tunnel_type", ""),
            "action": zt.get("action", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("tunnel_type", ""),
            record.get("action", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("tunnel_type"):
            clauses.append({"term": {"zeek.tunnel.tunnel_type": search_params["tunnel_type"]}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique tunnel record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP", style="yellow", no_wrap=True, max_width=36)
        table.add_column("Tunnel Type", no_wrap=True)
        table.add_column("Action", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            flow = f"{src_ip} → {dest_ip}"

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                rec.get("tunnel_type", "") or "—",
                rec.get("action", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--tunnel-type",
            dest="tunnel_type",
            help="Filter by tunnel type (Tunnel::IP, Tunnel::GRE, etc.)",
        )

    def describe_record(self, record: dict) -> str:
        tunnel_type = record.get("tunnel_type") or "?"
        action = record.get("action") or "?"
        return (
            f"tunnel {record.get('src_ip', '?')} → {record.get('dest_ip', '?')}"
            f" [{tunnel_type}: {action}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/tunnel"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Tunnel type filter", new.get("tunnel_type"))
        new["tunnel_type"] = val if val else None
