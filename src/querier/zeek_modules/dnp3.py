#!/usr/bin/env python3
"""Zeek DNP3 log module — SCADA protocol for utilities (electric, water, gas)."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class Dnp3Module(ZeekModule):
    DATASETS = ["dnp3"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.dnp3.function_request",
        "zeek.dnp3.function_reply",
        "zeek.dnp3.iin",
        "network.community_id",
        "event.dataset",
    ]

    WEB_CATEGORY = "ot"
    WEB_ICON = "fa-bolt"
    EXTRA_PARAMS = ["function"]
    WEB_COLUMNS = [
        ("Request", lambda r: r.get("function_request", "—") or "—"),
        ("Reply", lambda r: r.get("function_reply", "—") or "—"),
        ("IIN", lambda r: r.get("iin", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Request", lambda r: r.get("function_request", "—")),
        ("Reply", lambda r: r.get("function_reply", "—") or "—"),
        ("IIN", lambda r: r.get("iin", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zd = src.get("zeek", {}).get("dnp3", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "function_request": zd.get("function_request", ""),
            "function_reply": zd.get("function_reply", ""),
            "iin": zd.get("iin", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("function_request", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("function"):
            clauses.append(
                {"match_phrase": {"zeek.dnp3.function_request": search_params["function"]}}
            )

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique DNP3 record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP:Port", style="yellow", no_wrap=True, max_width=42)
        table.add_column("Request", no_wrap=True)
        table.add_column("Reply", no_wrap=True)
        table.add_column("IIN", no_wrap=True)
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
                rec.get("function_request", "") or "—",
                rec.get("function_reply", "") or "—",
                rec.get("iin", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--function",
            dest="function",
            help="Filter by DNP3 function request (substring match)",
        )

    def describe_record(self, record: dict) -> str:
        req = record.get("function_request") or "?"
        return f"dnp3 {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{req}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/dnp3"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Function request filter", new.get("function"))
        new["function"] = val if val else None
