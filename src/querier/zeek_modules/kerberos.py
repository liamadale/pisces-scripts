#!/usr/bin/env python3
"""Zeek kerberos log module — Kerberos authentication records."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class KerberosModule(ZeekModule):
    DATASETS = ["kerberos"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.kerberos.client",
        "zeek.kerberos.service",
        "zeek.kerberos.success",
        "zeek.kerberos.error_msg",
        "zeek.kerberos.from",
        "zeek.kerberos.till",
        "zeek.kerberos.cipher",
        "zeek.kerberos.forwardable",
        "zeek.kerberos.renewable",
        "zeek.kerberos.request_type",
        "zeek.kerberos.client_cert_subject",
        "zeek.kerberos.server_cert_subject",
        "network.community_id",
        "network.direction",
        "event.dataset",
    ]

    WEB_CATEGORY = "auth"
    WEB_ICON = "fa-key"
    EXTRA_PARAMS = ["client", "service", "request_type", "cipher", "failed_only"]
    WEB_COLUMNS = [
        ("Client", lambda r: r.get("client", "—") or "—"),
        ("Type", lambda r: r.get("request_type", "—") or "—"),
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
        ("Client", lambda r: r.get("client", "—")),
        ("Service", lambda r: r.get("service", "—")),
        ("Request Type", lambda r: r.get("request_type", "—")),
        (
            "Success",
            lambda r: "✓" if r.get("success") else ("✗" if r.get("success") is False else "—"),
        ),
        ("Error", lambda r: r.get("error_msg", "—") or "—"),
        ("Cipher", lambda r: r.get("cipher", "—") or "—"),
        (
            "Forwardable",
            lambda r: (
                "✓" if r.get("forwardable") else ("✗" if r.get("forwardable") is False else "—")
            ),
        ),
        (
            "Renewable",
            lambda r: "✓" if r.get("renewable") else ("✗" if r.get("renewable") is False else "—"),
        ),
        ("Valid From", lambda r: r.get("valid_from", "—") or "—"),
        ("Valid Till", lambda r: r.get("valid_till", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Direction", lambda r: r.get("direction", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zk = src.get("zeek", {}).get("kerberos", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "client": zk.get("client", ""),
            "service": zk.get("service", ""),
            "success": zk.get("success"),
            "error_msg": zk.get("error_msg", ""),
            "request_type": zk.get("request_type", ""),
            "cipher": zk.get("cipher", ""),
            "forwardable": zk.get("forwardable"),
            "renewable": zk.get("renewable"),
            "valid_from": zk.get("from", ""),
            "valid_till": zk.get("till", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction": src.get("network", {}).get("direction", ""),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("client", ""),
            record.get("service", ""),
            record.get("request_type", ""),
            record.get("success"),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("client"):
            clauses.append({"match_phrase": {"zeek.kerberos.client": search_params["client"]}})
        if search_params.get("service"):
            clauses.append({"match_phrase": {"zeek.kerberos.service": search_params["service"]}})
        if search_params.get("request_type"):
            clauses.append({"term": {"zeek.kerberos.request_type": search_params["request_type"]}})
        if search_params.get("cipher"):
            clauses.append({"term": {"zeek.kerberos.cipher": search_params["cipher"]}})
        if search_params.get("failed_only"):
            clauses.append({"term": {"zeek.kerberos.success": False}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique Kerberos auth record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Client", no_wrap=True, max_width=28, overflow="ellipsis")
        table.add_column("Service", no_wrap=True, max_width=28, overflow="ellipsis")
        table.add_column("Type", no_wrap=True)
        table.add_column("Auth", justify="center", no_wrap=True)
        table.add_column("Cipher", no_wrap=True, max_width=16, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            success = rec.get("success")
            auth_str = "✓" if success else ("✗" if success is False else "—")
            auth_col = (
                f"[green]{auth_str}[/green]"
                if success
                else (f"[red]{auth_str}[/red]" if success is False else auth_str)
            )

            req_type = rec.get("request_type", "") or "—"
            if req_type == "AS":
                req_col = f"[cyan]{req_type}[/cyan]"
            elif req_type == "TGS":
                req_col = f"[yellow]{req_type}[/yellow]"
            else:
                req_col = req_type

            cipher = rec.get("cipher", "") or "—"
            cipher_col = f"[orange1]{cipher}[/orange1]" if "RC4" in cipher else cipher

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", "") or "—",
                rec.get("client", "") or "—",
                rec.get("service", "") or "—",
                req_col,
                auth_col,
                cipher_col,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--client", dest="client", help="Filter by client principal")
        parser.add_argument("--service", dest="service", help="Filter by service principal")
        parser.add_argument(
            "--request-type",
            dest="request_type",
            choices=["AS", "TGS"],
            help="Filter by request type",
        )
        parser.add_argument("--cipher", dest="cipher", help="Filter by cipher (exact match)")
        parser.add_argument(
            "--failed-only",
            dest="failed_only",
            action="store_true",
            help="Show only failed authentication attempts",
        )

    def describe_record(self, record: dict) -> str:
        client = record.get("client") or "?"
        service = record.get("service") or "?"
        req = record.get("request_type") or ""
        return f"kerberos {client} → {service} [{req}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/kerberos"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Client filter (user@domain)", new.get("client"))
        new["client"] = val if val else None
        val = _ask("Service filter (service/host@domain)", new.get("service"))
        new["service"] = val if val else None
        val = _ask("Request type (AS/TGS)", new.get("request_type"))
        new["request_type"] = val if val else None
        val = _ask("Cipher filter", new.get("cipher"))
        new["cipher"] = val if val else None
        raw = _ask("Failed only (y/n)", "y" if new.get("failed_only") else "n")
        new["failed_only"] = raw.lower() in ("y", "yes")
