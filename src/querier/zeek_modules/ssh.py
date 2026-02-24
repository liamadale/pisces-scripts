#!/usr/bin/env python3
"""Zeek ssh log module — SSH connection and authentication records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class SshModule(ZeekModule):
    DATASETS = ["ssh"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.ssh.auth_success",
        "zeek.ssh.auth_attempts",
        "zeek.ssh.client",
        "zeek.ssh.server",
        "zeek.ssh.version",
        "zeek.ssh.direction",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("ssh_failed_only"):
            clauses.append({"term": {"zeek.ssh.auth_success": False}})
        elif search_params.get("ssh_auth_result") is not None:
            val_str = str(search_params["ssh_auth_result"]).lower()
            val = val_str in ("true", "1", "yes")
            clauses.append({"term": {"zeek.ssh.auth_success": val}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        ssh = src.get("zeek", {}).get("ssh", {})
        return {
            "timestamp":       src.get("@timestamp", ""),
            "sensor":          src.get("host", {}).get("name", ""),
            "log_type":        src.get("event", {}).get("dataset", ""),
            "src_ip":          src.get("source", {}).get("ip", ""),
            "src_port":        src.get("source", {}).get("port"),
            "dest_ip":         src.get("destination", {}).get("ip", ""),
            "dest_port":       src.get("destination", {}).get("port"),
            "ssh_auth_success": ssh.get("auth_success"),
            "ssh_auth_attempts": ssh.get("auth_attempts"),
            "ssh_client":      ssh.get("client", ""),
            "ssh_server":      ssh.get("server", ""),
            "ssh_version":     ssh.get("version"),
            "ssh_direction":   ssh.get("direction", ""),
            "_raw":            src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("ssh_auth_success"),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SSH flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("Version", no_wrap=True)
        table.add_column("Auth", justify="center", no_wrap=True)
        table.add_column("Attempts", justify="right", no_wrap=True)
        table.add_column("Client", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            auth = rec.get("ssh_auth_success")
            auth_str = "[green]✓[/green]" if auth is True else ("[red]✗[/red]" if auth is False else "—")
            ver = rec.get("ssh_version")
            ver_str = str(ver) if ver is not None else "—"
            attempts = rec.get("ssh_auth_attempts")
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                "→",
                rec.get("dest_ip", ""),
                str(rec["dest_port"]) if rec.get("dest_port") is not None else "—",
                ver_str,
                auth_str,
                str(attempts) if attempts is not None else "—",
                rec.get("ssh_client", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--failed-only", dest="ssh_failed_only", action="store_true",
            help="Show only failed SSH authentication attempts",
        )
        parser.add_argument(
            "--auth-result", dest="ssh_auth_result", choices=["true", "false"],
            help="Filter by auth result (term on zeek.ssh.auth_success)",
        )

    def describe_record(self, record: dict) -> str:
        auth = record.get("ssh_auth_success")
        result = "success" if auth is True else ("failed" if auth is False else "?")
        return (
            f"ssh {record.get('src_ip', '?')} → {record.get('dest_ip', '?')}:{record.get('dest_port', '?')}"
            f" [{result}]"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/ssh"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        raw = _ask("Failed only (y/n)", "y" if new.get("ssh_failed_only") else "n")
        new["ssh_failed_only"] = raw.lower() in ("y", "yes")
        if not new["ssh_failed_only"]:
            val = _ask("Auth result filter (true/false/blank)", new.get("ssh_auth_result"))
            new["ssh_auth_result"] = val if val in ("true", "false") else None
