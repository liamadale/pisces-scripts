#!/usr/bin/env python3
"""Zeek rdp log module — Remote Desktop Protocol session records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class RdpModule(ZeekModule):
    DATASETS = ["rdp"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.rdp.cookie",
        "zeek.rdp.result",
        "zeek.rdp.security_protocol",
        "zeek.rdp.client_name",
        "zeek.rdp.client_build",
        "zeek.rdp.keyboard_layout",
        "zeek.rdp.encryption_method",
        "network.community_id",
        "network.direction",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("rdp_result"):
            clauses.append({"term": {"zeek.rdp.result": search_params["rdp_result"]}})
        if search_params.get("rdp_cookie"):
            clauses.append({"match_phrase": {"zeek.rdp.cookie": search_params["rdp_cookie"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        rdp = src.get("zeek", {}).get("rdp", {})
        return {
            "timestamp":       src.get("@timestamp", ""),
            "sensor":          src.get("host", {}).get("name", ""),
            "log_type":        src.get("event", {}).get("dataset", ""),
            "src_ip":          src.get("source", {}).get("ip", ""),
            "src_port":        src.get("source", {}).get("port"),
            "dest_ip":         src.get("destination", {}).get("ip", ""),
            "dest_port":       src.get("destination", {}).get("port"),
            "rdp_cookie":      rdp.get("cookie", ""),
            "rdp_result":      rdp.get("result", ""),
            "rdp_security":    rdp.get("security_protocol", ""),
            "rdp_client_name": rdp.get("client_name", ""),
            "rdp_client_build": rdp.get("client_build", ""),
            "rdp_keyboard":    rdp.get("keyboard_layout", ""),
            "rdp_encryption":  rdp.get("encryption_method", ""),
            "community_id":    src.get("network", {}).get("community_id", ""),
            "direction":       src.get("network", {}).get("direction", ""),
            "_raw":            src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("rdp_cookie", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp",    lambda r: r.get("timestamp", "—")),
        ("Sensor",       lambda r: r.get("sensor", "—")),
        ("Src IP",       lambda r: r.get("src_ip", "—")),
        ("Dst IP",       lambda r: r.get("dest_ip", "—") or "—"),
        ("Cookie",       lambda r: r.get("rdp_cookie", "—") or "—"),
        ("Result",       lambda r: r.get("rdp_result", "—") or "—"),
        ("Security",     lambda r: r.get("rdp_security", "—") or "—"),
        ("Client Name",  lambda r: r.get("rdp_client_name", "—") or "—"),
        ("Build",        lambda r: r.get("rdp_client_build", "—") or "—"),
        ("Comm ID",      lambda r: r.get("community_id", "—") or "—"),
        ("Direction",    lambda r: r.get("direction", "—") or "—"),
        ("Freq",         lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique RDP session(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=32, overflow="ellipsis")
        table.add_column("Cookie", no_wrap=True, max_width=15, overflow="ellipsis")
        table.add_column("Result", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "")
            dest_ip = rec.get("dest_ip", "")
            flow = f"{src_ip} → {dest_ip}"
            table.add_row(
                str(idx),
                rec["timestamp"][11:16],
                _sensor_str(rec),
                flow,
                rec.get("rdp_cookie", "") or "—",
                rec.get("rdp_result", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--result", dest="rdp_result",
            help="Filter by RDP result (term on zeek.rdp.result, e.g. fail)",
        )
        parser.add_argument(
            "--cookie", dest="rdp_cookie",
            help="Filter by RDP cookie (match_phrase on zeek.rdp.cookie)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"rdp {record.get('src_ip', '?')} → {record.get('dest_ip', '?')}:{record.get('dest_port', '?')}"
            f" [{record.get('rdp_result', '?')}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/rdp"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("RDP result filter", new.get("rdp_result"))
        new["rdp_result"] = val if val else None
        val = _ask("RDP cookie filter", new.get("rdp_cookie"))
        new["rdp_cookie"] = val if val else None
