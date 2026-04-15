#!/usr/bin/env python3
"""Zeek ntlm log module — NTLM authentication records."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class NtlmModule(ZeekModule):
    DATASETS = ["ntlm"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.ntlm.username",
        "zeek.ntlm.domainname",
        "zeek.ntlm.hostname",
        "zeek.ntlm.server_nb_computer_name",
        "zeek.ntlm.server_dns_computer_name",
        "zeek.ntlm.server_tree_name",
        "zeek.ntlm.success",
        "zeek.ntlm.status",
        "network.community_id",
        "network.direction",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    WEB_CATEGORY = "auth"
    WEB_COLUMNS = [
        ("Username", lambda r: r.get("username", "—") or "—"),
        ("Domain", lambda r: r.get("domain", "—") or "—"),
        (
            "Auth",
            lambda r: "✓" if r.get("success") else ("✗" if r.get("success") is False else "—"),
        ),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Username", lambda r: r.get("username", "—")),
        ("Domain", lambda r: r.get("domain", "—")),
        ("Client Hostname", lambda r: r.get("client_hostname", "—") or "—"),
        ("Server NB Name", lambda r: r.get("server_nb_name", "—") or "—"),
        ("Server DNS Name", lambda r: r.get("server_dns_name", "—") or "—"),
        ("Server Tree", lambda r: r.get("server_tree", "—") or "—"),
        (
            "Success",
            lambda r: "✓" if r.get("success") else ("✗" if r.get("success") is False else "—"),
        ),
        ("Status", lambda r: r.get("status", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Direction", lambda r: r.get("direction", "—") or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zn = src.get("zeek", {}).get("ntlm", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "username": zn.get("username", ""),
            "domain": zn.get("domainname", ""),
            "client_hostname": zn.get("hostname", ""),
            "server_nb_name": zn.get("server_nb_computer_name", ""),
            "server_dns_name": zn.get("server_dns_computer_name", ""),
            "server_tree": zn.get("server_tree_name", ""),
            "success": zn.get("success"),
            "status": zn.get("status", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction": src.get("network", {}).get("direction", ""),
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("username", ""),
            record.get("domain", ""),
            record.get("success"),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("username"):
            clauses.append({"match_phrase": {"zeek.ntlm.username": search_params["username"]}})
        if search_params.get("domain"):
            clauses.append({"match_phrase": {"zeek.ntlm.domainname": search_params["domain"]}})
        if search_params.get("failed_only"):
            clauses.append({"term": {"zeek.ntlm.success": False}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique NTLM auth record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Username", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Domain", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Dst IP", no_wrap=True)
        table.add_column("Auth", justify="center", no_wrap=True)
        table.add_column("Status", no_wrap=True, max_width=16, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            success = rec.get("success")
            auth_str = "✓" if success else ("✗" if success is False else "—")
            auth_col = (
                f"[green]{auth_str}[/green]"
                if success
                else (f"[red]{auth_str}[/red]" if success is False else auth_str)
            )

            username = rec.get("username", "") or "—"
            freq = rec.get("freq", 1)
            # Highlight potential password spray
            username_col = (
                f"[yellow]{username}[/yellow]"
                if username.upper() == "GUEST"
                else (f"[orange1]{username}[/orange1]" if freq > 10 and not success else username)
            )

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", "") or "—",
                username_col,
                rec.get("domain", "") or "—",
                rec.get("dest_ip", "") or "—",
                auth_col,
                rec.get("status", "") or "—",
                str(freq),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--username", dest="username", help="Filter by username (match_phrase)")
        parser.add_argument("--domain", dest="domain", help="Filter by domain name (match_phrase)")
        parser.add_argument(
            "--failed-only",
            dest="failed_only",
            action="store_true",
            help="Show only failed authentication attempts",
        )

    def describe_record(self, record: dict) -> str:
        username = record.get("username") or "?"
        domain = record.get("domain") or ""
        full = f"{domain}\\{username}" if domain else username
        return f"ntlm {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{full}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/ntlm"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Username filter", new.get("username"))
        new["username"] = val if val else None
        val = _ask("Domain filter", new.get("domain"))
        new["domain"] = val if val else None
        raw = _ask("Failed only (y/n)", "y" if new.get("failed_only") else "n")
        new["failed_only"] = raw.lower() in ("y", "yes")
