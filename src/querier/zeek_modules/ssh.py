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
        "network.community_id",
        "network.direction",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
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
            "community_id":    src.get("network", {}).get("community_id", ""),
            "direction":       src.get("network", {}).get("direction", ""),
            "risk_score":      src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw":            src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("ssh_auth_success"),
        )

    DETAIL_FIELDS = [
        ("Timestamp",    lambda r: r.get("timestamp", "—")),
        ("Sensor",       lambda r: r.get("sensor", "—")),
        ("Src IP",       lambda r: r.get("src_ip", "—")),
        ("Dst IP",       lambda r: r.get("dest_ip", "—") or "—"),
        ("Dst Port",     lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("SSH Version",  lambda r: str(r["ssh_version"]) if r.get("ssh_version") is not None else "—"),
        ("Auth",         lambda r: "✓" if r.get("ssh_auth_success") is True else ("✗" if r.get("ssh_auth_success") is False else "—")),
        ("Attempts",     lambda r: str(r["ssh_auth_attempts"]) if r.get("ssh_auth_attempts") is not None else "—"),
        ("Client",       lambda r: r.get("ssh_client", "—") or "—"),
        ("Comm ID",      lambda r: r.get("community_id", "—") or "—"),
        ("Direction",    lambda r: r.get("direction", "—") or "—"),
        ("Risk Score",      lambda r: str(r.get("risk_score"))      if r.get("risk_score")      else "—"),
        ("Risk Score Norm", lambda r: str(r.get("risk_score_norm")) if r.get("risk_score_norm") else "—"),
        ("Freq",         lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SSH flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=38, overflow="ellipsis")
        table.add_column("Auth", justify="center", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            auth = rec.get("ssh_auth_success")
            auth_str = "[green]✓[/green]" if auth is True else ("[red]✗[/red]" if auth is False else "—")
            src_ip = rec.get("src_ip", "")
            dest_ip = rec.get("dest_ip", "")
            dest_port = rec.get("dest_port")
            flow = f"{src_ip} → {dest_ip}:{dest_port}"
            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                auth_str,
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
