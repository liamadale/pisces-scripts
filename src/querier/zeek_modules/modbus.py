#!/usr/bin/env python3
"""Zeek Modbus log module — OT/SCADA protocol for PLCs and RTUs."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class ModbusModule(ZeekModule):
    DATASETS = ["modbus"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.modbus.function",
        "zeek.modbus.exception",
        "zeek.modbus.track_address",
        "network.community_id",
        "event.dataset",
    ]

    WEB_CATEGORY = "ot"
    WEB_ICON = "fa-microchip"
    EXTRA_PARAMS = ["function", "exceptions_only"]
    WEB_COLUMNS = [
        ("Function", lambda r: r.get("function", "—") or "—"),
        ("Exception", lambda r: r.get("exception", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Function", lambda r: r.get("function", "—")),
        ("Exception", lambda r: r.get("exception", "—") or "—"),
        (
            "Track Address",
            lambda r: str(r.get("track_address")) if r.get("track_address") is not None else "—",
        ),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zm = src.get("zeek", {}).get("modbus", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "function": zm.get("function", ""),
            "exception": zm.get("exception", ""),
            "track_address": zm.get("track_address"),
            "community_id": src.get("network", {}).get("community_id", ""),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("function", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("function"):
            clauses.append({"match_phrase": {"zeek.modbus.function": search_params["function"]}})
        if search_params.get("exceptions_only"):
            post_filters.append(lambda r: bool(r.get("exception")))

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique Modbus record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP:Port", style="yellow", no_wrap=True, max_width=42)
        table.add_column("Function", no_wrap=True)
        table.add_column("Exception", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            dest_port = str(rec.get("dest_port")) if rec.get("dest_port") is not None else ""
            dest_str = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
            flow = f"{src_ip} → {dest_str}"

            func = rec.get("function", "") or "—"
            exception = rec.get("exception", "") or "—"

            # Write functions in orange; exceptions in red
            if exception != "—":
                row_style = "red"
            elif func.startswith("Write"):
                row_style = "orange1"
            else:
                row_style = ""

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                func,
                exception,
                str(rec["freq"]),
                style=row_style if row_style else None,
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--function",
            dest="function",
            help="Filter by Modbus function (e.g. 'Read Coils', 'Write Single Register')",
        )
        parser.add_argument(
            "--exceptions-only",
            dest="exceptions_only",
            action="store_true",
            default=False,
            help="Show only records with exception codes",
        )

    def describe_record(self, record: dict) -> str:
        func = record.get("function") or "?"
        return f"modbus {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{func}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/modbus"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Function filter", new.get("function"))
        new["function"] = val if val else None
        raw = _ask("Exceptions only (y/n)", "y" if new.get("exceptions_only") else "n")
        new["exceptions_only"] = raw.lower() in ("y", "yes")
