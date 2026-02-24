#!/usr/bin/env python3
"""Zeek conn log module — TCP/UDP/ICMP connection records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _first, _fmt_bytes, _fmt_dur, _sensor_str, console


class ConnModule(ZeekModule):
    DATASETS = ["conn"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "network.transport",
        "network.protocol",
        "network.community_id",
        "source.bytes",
        "destination.bytes",
        "zeek.conn.duration",
        "zeek.conn.conn_state",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        return []

    def parse_hit(self, src: dict) -> dict:
        net = src.get("network", {})
        return {
            "timestamp":    src.get("@timestamp", ""),
            "sensor":       src.get("host", {}).get("name", ""),
            "log_type":     src.get("event", {}).get("dataset", ""),
            "src_ip":       src.get("source", {}).get("ip", ""),
            "src_port":     src.get("source", {}).get("port"),
            "dest_ip":      src.get("destination", {}).get("ip", ""),
            "dest_port":    src.get("destination", {}).get("port"),
            "proto":        _first(net.get("transport", "")),
            "app_proto":    _first(net.get("protocol", "")),
            "community_id": net.get("community_id"),
            "bytes_orig":   src.get("source", {}).get("bytes"),
            "bytes_resp":   src.get("destination", {}).get("bytes"),
            "duration":     src.get("zeek", {}).get("conn", {}).get("duration"),
            "conn_state":   src.get("zeek", {}).get("conn", {}).get("conn_state"),
            "_raw":         src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("dest_port"),
            record.get("proto", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("Proto", no_wrap=True)
        table.add_column("App", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Dur", justify="right", no_wrap=True)
        table.add_column("↑Bytes", justify="right", no_wrap=True)
        table.add_column("↓Bytes", justify="right", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                str(rec["src_port"]) if rec.get("src_port") is not None else "—",
                "→",
                rec.get("dest_ip", ""),
                str(rec["dest_port"]) if rec.get("dest_port") is not None else "—",
                rec.get("proto") or "—",
                rec.get("app_proto") or "—",
                rec.get("conn_state") or "—",
                _fmt_dur(rec.get("duration")),
                _fmt_bytes(rec.get("bytes_orig")),
                _fmt_bytes(rec.get("bytes_resp")),
                str(rec["freq"]),
            )

        console.print(table)

    def describe_record(self, record: dict) -> str:
        return (
            f"conn {record.get('src_ip', '?')} → "
            f"{record.get('dest_ip', '?')}:{record.get('dest_port', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/conn"
