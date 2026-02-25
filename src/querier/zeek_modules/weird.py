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
        "network.community_id",
        "network.direction",
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
            "weird_peer":   weird.get("peer", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction":    src.get("network", {}).get("direction", ""),
            "_raw":         src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("weird_name", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp",   lambda r: r.get("timestamp", "—")),
        ("Sensor",      lambda r: r.get("sensor", "—")),
        ("Src IP",      lambda r: r.get("src_ip", "—")),
        ("Dst IP",      lambda r: r.get("dest_ip", "—") or "—"),
        ("Weird Name",  lambda r: r.get("weird_name", "—") or "—"),
        ("Additional",  lambda r: r.get("weird_addl", "—") or "—"),
        ("Comm ID",     lambda r: r.get("community_id", "—") or "—"),
        ("Direction",   lambda r: r.get("direction", "—") or "—"),
        ("Freq",        lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique weird event(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=32, overflow="ellipsis")
        table.add_column("Weird Name", no_wrap=True, max_width=25, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "")
            dest_ip = rec.get("dest_ip", "")
            flow = f"{src_ip} → {dest_ip}"
            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                rec.get("weird_name", "") or "—",
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
