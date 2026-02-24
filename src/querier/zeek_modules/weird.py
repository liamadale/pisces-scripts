#!/usr/bin/env python3
"""Zeek weird log module — unusual protocol behaviour records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class WeirdModule(ZeekModule):
    DATASETS = ["weird"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.weird.name",
        "zeek.weird.addl",
        "zeek.weird.peer",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("weird_name"):
            clauses.append({"term": {"zeek.weird.name": search_params["weird_name"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        weird = src.get("zeek", {}).get("weird", {})
        return {
            "timestamp":  src.get("@timestamp", ""),
            "sensor":     src.get("host", {}).get("name", ""),
            "log_type":   src.get("event", {}).get("dataset", ""),
            "src_ip":     src.get("source", {}).get("ip", ""),
            "src_port":   src.get("source", {}).get("port"),
            "dest_ip":    src.get("destination", {}).get("ip", ""),
            "dest_port":  src.get("destination", {}).get("port"),
            "weird_name": weird.get("name", ""),
            "weird_addl": weird.get("addl", ""),
            "weird_peer": weird.get("peer", ""),
            "_raw":       src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("weird_name", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique weird event(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Weird Name", no_wrap=True)
        table.add_column("Additional", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                "→",
                rec.get("dest_ip", "") or "—",
                rec.get("weird_name", "") or "—",
                rec.get("weird_addl", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--name", dest="weird_name",
            help="Filter by weird event name (term on zeek.weird.name)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"weird {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} "
            f"[{record.get('weird_name', '?')}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/weird"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Weird name filter", new.get("weird_name"))
        new["weird_name"] = val if val else None
