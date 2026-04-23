#!/usr/bin/env python3
"""Zeek dhcp log module — DHCP lease records with hostname-to-IP-to-MAC mappings."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _fmt_dur, _sensor_str, console


class DhcpModule(ZeekModule):
    DATASETS = ["dhcp"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "destination.ip",
        "zeek.dhcp.client_addr",
        "zeek.dhcp.server_addr",
        "zeek.dhcp.assigned_ip",
        "zeek.dhcp.client_message",
        "zeek.dhcp.server_message",
        "zeek.dhcp.mac",
        "zeek.dhcp.host_name",
        "zeek.dhcp.client_fqdn",
        "zeek.dhcp.domain",
        "zeek.dhcp.lease_time",
        "zeek.dhcp.msg_types",
        "zeek.dhcp.requested_ip",
        "event.dataset",
    ]

    WEB_CATEGORY = "network"
    WEB_ICON = "fa-address-card"
    EXTRA_PARAMS = ["hostname", "mac", "assigned_ip"]
    WEB_COLUMNS = [
        ("MAC", lambda r: r.get("mac", "—") or "—"),
        ("Hostname", lambda r: r.get("hostname", "—") or "—"),
        ("Assigned IP", lambda r: r.get("assigned_ip", "—") or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Client Addr", lambda r: r.get("src_ip", "—")),
        ("Server Addr", lambda r: r.get("dest_ip", "—")),
        ("Assigned IP", lambda r: r.get("assigned_ip", "—")),
        ("MAC", lambda r: r.get("mac", "—")),
        ("Hostname", lambda r: r.get("hostname", "—") or "—"),
        ("Client FQDN", lambda r: r.get("client_fqdn", "—") or "—"),
        ("Domain", lambda r: r.get("domain", "—") or "—"),
        ("Lease Time", lambda r: _fmt_dur(r.get("lease_time"))),
        ("Msg Types", lambda r: r.get("msg_types", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zd = src.get("zeek", {}).get("dhcp", {})
        # Prefer ECS source.ip / destination.ip; fall back to protocol-specific fields.
        src_ip = src.get("source", {}).get("ip") or zd.get("client_addr", "")
        dest_ip = src.get("destination", {}).get("ip") or zd.get("server_addr", "")
        msg_types = zd.get("msg_types")
        if isinstance(msg_types, list):
            msg_types = " → ".join(msg_types)
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "assigned_ip": zd.get("assigned_ip", ""),
            "mac": zd.get("mac", ""),
            "hostname": zd.get("host_name", ""),
            "client_fqdn": zd.get("client_fqdn", ""),
            "domain": zd.get("domain", ""),
            "lease_time": zd.get("lease_time"),
            "msg_types": msg_types or "",
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("mac", ""),
            record.get("assigned_ip", ""),
            record.get("hostname", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []
        if search_params.get("hostname"):
            clauses.append({"match_phrase": {"zeek.dhcp.host_name": search_params["hostname"]}})
        if search_params.get("mac"):
            clauses.append({"term": {"zeek.dhcp.mac": search_params["mac"]}})
        if search_params.get("assigned_ip"):
            clauses.append({"term": {"zeek.dhcp.assigned_ip": search_params["assigned_ip"]}})
        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique DHCP lease(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("MAC", style="yellow", no_wrap=True)
        table.add_column("Hostname", no_wrap=True, max_width=24, overflow="ellipsis")
        table.add_column("Assigned IP", no_wrap=True)
        table.add_column("DHCP Server", no_wrap=True)
        table.add_column("Lease", justify="right", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("mac", "") or "—",
                rec.get("hostname", "") or "—",
                rec.get("assigned_ip", "") or "—",
                rec.get("dest_ip", "") or "—",
                _fmt_dur(rec.get("lease_time")),
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--hostname", dest="hostname", help="Filter by client hostname (match_phrase)"
        )
        parser.add_argument("--mac", dest="mac", help="Filter by MAC address (exact match)")
        parser.add_argument(
            "--assigned-ip", dest="assigned_ip", help="Filter by assigned IP (exact match)"
        )

    def describe_record(self, record: dict) -> str:
        hostname = record.get("hostname") or record.get("assigned_ip") or "?"
        return f"dhcp {record.get('mac', '?')} → {hostname}"

    def fp_signature(self, record: dict) -> str:
        return "zeek/dhcp"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Hostname filter", new.get("hostname"))
        new["hostname"] = val if val else None
        val = _ask("MAC filter", new.get("mac"))
        new["mac"] = val if val else None
        val = _ask("Assigned IP filter", new.get("assigned_ip"))
        new["assigned_ip"] = val if val else None
