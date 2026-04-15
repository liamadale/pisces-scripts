#!/usr/bin/env python3
"""Zeek DPD log module — dynamic protocol detection failures."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class DpdModule(ZeekModule):
    DATASETS = ["dpd"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.dpd.proto",
        "zeek.dpd.analyzer",
        "zeek.dpd.failure_reason",
        "network.community_id",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    WEB_CATEGORY = "diagnostic"
    WEB_COLUMNS = [
        ("Analyzer", lambda r: r.get("analyzer", "—") or "—"),
        ("Failure Reason", lambda r: r.get("failure_reason", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Proto", lambda r: r.get("proto", "—")),
        ("Analyzer", lambda r: r.get("analyzer", "—")),
        ("Failure Reason", lambda r: r.get("failure_reason", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zd = src.get("zeek", {}).get("dpd", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "proto": zd.get("proto", ""),
            "analyzer": zd.get("analyzer", ""),
            "failure_reason": zd.get("failure_reason", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("dest_port"),
            record.get("analyzer", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("analyzer"):
            clauses.append({"term": {"zeek.dpd.analyzer": search_params["analyzer"]}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique DPD failure(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP:Port", style="yellow", no_wrap=True, max_width=42)
        table.add_column("Proto", no_wrap=True)
        table.add_column("Analyzer", no_wrap=True)
        table.add_column("Failure Reason", no_wrap=True, max_width=36, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            dest_port = str(rec.get("dest_port")) if rec.get("dest_port") is not None else ""
            dest_str = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
            flow = f"{src_ip} → {dest_str}"

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                rec.get("proto", "") or "—",
                rec.get("analyzer", "") or "—",
                rec.get("failure_reason", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--analyzer",
            dest="analyzer",
            help="Filter by DPD analyzer name (exact match)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"dpd {record.get('src_ip', '?')} → {record.get('dest_ip', '?')}:"
            f"{record.get('dest_port', '?')} [{record.get('analyzer', '?')}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/dpd"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Analyzer filter", new.get("analyzer"))
        new["analyzer"] = val if val else None
