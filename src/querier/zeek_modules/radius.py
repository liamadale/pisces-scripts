#!/usr/bin/env python3
"""Zeek radius log module — RADIUS authentication records (VPN/802.1X)."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class RadiusModule(ZeekModule):
    DATASETS = ["radius"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.radius.username",
        "zeek.radius.result",
        "zeek.radius.mac",
        "zeek.radius.framed_addr",
        "zeek.radius.remote_ip",
        "zeek.radius.connect_info",
        "zeek.radius.reply_msg",
        "zeek.radius.ttl",
        "network.community_id",
        "event.dataset",
    ]

    WEB_CATEGORY = "auth"
    WEB_ICON = "fa-wifi"
    EXTRA_PARAMS = ["username", "mac", "failed_only"]
    WEB_COLUMNS = [
        ("Username", lambda r: r.get("username", "—") or "—"),
        ("Result", lambda r: r.get("result", "—") or "—"),
        ("Assigned IP", lambda r: r.get("framed_addr", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Username", lambda r: r.get("username", "—")),
        ("Result", lambda r: r.get("result", "—")),
        ("MAC", lambda r: r.get("mac", "—") or "—"),
        ("Assigned IP", lambda r: r.get("framed_addr", "—") or "—"),
        ("Remote IP", lambda r: r.get("remote_ip", "—") or "—"),
        ("Reply Msg", lambda r: r.get("reply_msg", "—") or "—"),
        ("TTL", lambda r: str(r.get("ttl")) if r.get("ttl") else "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zr = src.get("zeek", {}).get("radius", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "username": zr.get("username", ""),
            "result": zr.get("result", ""),
            "mac": zr.get("mac", ""),
            "framed_addr": zr.get("framed_addr", ""),
            "remote_ip": zr.get("remote_ip", ""),
            "reply_msg": zr.get("reply_msg", ""),
            "ttl": zr.get("ttl"),
            "community_id": src.get("network", {}).get("community_id", ""),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("username", ""),
            record.get("result", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("username"):
            clauses.append({"match_phrase": {"zeek.radius.username": search_params["username"]}})
        if search_params.get("mac"):
            clauses.append({"term": {"zeek.radius.mac": search_params["mac"]}})
        if search_params.get("failed_only"):
            clauses.append({"term": {"zeek.radius.result": "failed"}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique RADIUS auth record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Username", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("MAC", no_wrap=True)
        table.add_column("Result", no_wrap=True)
        table.add_column("Assigned IP", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            result = rec.get("result", "") or "—"
            result_lower = result.lower()
            if result_lower == "success":
                result_col = f"[green]{result}[/green]"
            elif result_lower == "failed":
                result_col = f"[red]{result}[/red]"
            else:
                result_col = result

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", "") or "—",
                rec.get("username", "") or "—",
                rec.get("mac", "") or "—",
                result_col,
                rec.get("framed_addr", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--username", dest="username", help="Filter by username (match_phrase)")
        parser.add_argument("--mac", dest="mac", help="Filter by MAC address (exact match)")
        parser.add_argument(
            "--failed-only",
            dest="failed_only",
            action="store_true",
            help="Show only failed authentication attempts",
        )

    def describe_record(self, record: dict) -> str:
        username = record.get("username") or "?"
        result = record.get("result") or "?"
        return (
            f"radius {record.get('src_ip', '?')} → {record.get('dest_ip', '?')}"
            f" [{username}: {result}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/radius"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Username filter", new.get("username"))
        new["username"] = val if val else None
        val = _ask("MAC filter", new.get("mac"))
        new["mac"] = val if val else None
        raw = _ask("Failed only (y/n)", "y" if new.get("failed_only") else "n")
        new["failed_only"] = raw.lower() in ("y", "yes")
