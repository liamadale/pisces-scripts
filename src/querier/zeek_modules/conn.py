#!/usr/bin/env python3
"""Zeek conn log module — TCP/UDP/ICMP connection records."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _first, _fmt_bytes, _fmt_dur, _sensor_str, console


class ConnModule(ZeekModule):
    WEB_CATEGORY = "network"
    WEB_ICON = "fa-network-wired"
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
        "network.direction",
        "source.bytes",
        "destination.bytes",
        "zeek.conn.duration",
        "zeek.conn.conn_state",
        "event.dataset",
    ]

    WEB_COLUMNS = [
        ("App", lambda r: r.get("app_proto") or "—"),
        ("↑ Bytes", lambda r: _fmt_bytes(r.get("bytes_orig"))),
        ("↓ Bytes", lambda r: _fmt_bytes(r.get("bytes_resp"))),
    ]

    def build_extra_must(self, search_params: dict) -> tuple:
        return [], []

    def parse_hit(self, src: dict) -> dict:
        net = src.get("network", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "proto": _first(net.get("transport", "")),
            "app_proto": _first(net.get("protocol", "")),
            "community_id": net.get("community_id", ""),
            "direction": net.get("direction", ""),
            "bytes_orig": src.get("source", {}).get("bytes"),
            "bytes_resp": src.get("destination", {}).get("bytes"),
            "duration": src.get("zeek", {}).get("conn", {}).get("duration"),
            "conn_state": src.get("zeek", {}).get("conn", {}).get("conn_state"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("dest_port"),
            record.get("proto", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        (
            "Src Port",
            lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—",
        ),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        (
            "Dst Port",
            lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—",
        ),
        ("Proto", lambda r: r.get("proto") or "—"),
        ("App", lambda r: r.get("app_proto") or "—"),
        ("State", lambda r: r.get("conn_state") or "—"),
        ("Duration", lambda r: _fmt_dur(r.get("duration"))),
        ("↑ Bytes", lambda r: _fmt_bytes(r.get("bytes_orig"))),
        ("↓ Bytes", lambda r: _fmt_bytes(r.get("bytes_resp"))),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Direction", lambda r: r.get("direction", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=40, overflow="ellipsis")
        table.add_column("App/State", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "")
            src_port = rec.get("src_port")
            dest_ip = rec.get("dest_ip", "")
            dest_port = rec.get("dest_port")
            flow = f"{src_ip}:{src_port} → {dest_ip}:{dest_port}"
            app_proto = rec.get("app_proto") or ""
            proto = rec.get("proto") or ""
            conn_state = rec.get("conn_state") or ""
            app_state = f"{app_proto or proto}/{conn_state}" if (app_proto or proto) else conn_state
            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                app_state or "—",
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
