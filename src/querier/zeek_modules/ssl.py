#!/usr/bin/env python3
"""Zeek ssl log module — TLS/SSL handshake records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class SslModule(ZeekModule):
    DATASETS = ["ssl"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.ssl.server_name",
        "zeek.ssl.version",
        "zeek.ssl.cipher",
        "zeek.ssl.established",
        "zeek.ssl.validation_status",
        "zeek.ssl.subject",
        "zeek.ssl.issuer",
        "network.community_id",
        "network.direction",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("ssl_sni"):
            clauses.append({"match_phrase": {"zeek.ssl.server_name": search_params["ssl_sni"]}})
        if search_params.get("ssl_invalid_only"):
            # Exclude records where validation is "ok" (invalid = anything else)
            clauses.append({
                "bool": {
                    "must_not": [{"term": {"zeek.ssl.validation_status": "ok"}}]
                }
            })
        return clauses

    def parse_hit(self, src: dict) -> dict:
        ssl = src.get("zeek", {}).get("ssl", {})
        return {
            "timestamp":         src.get("@timestamp", ""),
            "sensor":            src.get("host", {}).get("name", ""),
            "log_type":          src.get("event", {}).get("dataset", ""),
            "src_ip":            src.get("source", {}).get("ip", ""),
            "src_port":          src.get("source", {}).get("port"),
            "dest_ip":           src.get("destination", {}).get("ip", ""),
            "dest_port":         src.get("destination", {}).get("port"),
            "ssl_server_name":   ssl.get("server_name", ""),
            "ssl_version":       ssl.get("version", ""),
            "ssl_cipher":        ssl.get("cipher", ""),
            "ssl_established":   ssl.get("established"),
            "ssl_validation":    ssl.get("validation_status", ""),
            "ssl_subject":       ssl.get("subject", ""),
            "ssl_issuer":        ssl.get("issuer", ""),
            "community_id":      src.get("network", {}).get("community_id", ""),
            "direction":         src.get("network", {}).get("direction", ""),
            "_raw":              src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("ssl_server_name", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp",   lambda r: r.get("timestamp", "—")),
        ("Sensor",      lambda r: r.get("sensor", "—")),
        ("Src IP",      lambda r: r.get("src_ip", "—")),
        ("Src Port",    lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP",      lambda r: r.get("dest_ip", "—") or "—"),
        ("Dst Port",    lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("SNI",         lambda r: r.get("ssl_server_name", "—") or "—"),
        ("Version",     lambda r: r.get("ssl_version", "—") or "—"),
        ("Established", lambda r: "✓" if r.get("ssl_established") is True else ("✗" if r.get("ssl_established") is False else "—")),
        ("Validation",  lambda r: r.get("ssl_validation", "—") or "—"),
        ("Comm ID",     lambda r: r.get("community_id", "—") or "—"),
        ("Direction",   lambda r: r.get("direction", "—") or "—"),
        ("Freq",        lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SSL/TLS flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=38, overflow="ellipsis")
        table.add_column("SNI", no_wrap=True, max_width=30, overflow="ellipsis")
        table.add_column("Est", justify="center", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            est = rec.get("ssl_established")
            est_str = "✓" if est is True else ("✗" if est is False else "—")
            src_ip = rec.get("src_ip", "")
            dest_ip = rec.get("dest_ip", "")
            dest_port = rec.get("dest_port")
            flow = f"{src_ip} → {dest_ip}:{dest_port}"
            table.add_row(
                str(idx),
                rec["timestamp"][11:16],
                _sensor_str(rec),
                flow,
                rec.get("ssl_server_name", "") or "—",
                est_str,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--sni", dest="ssl_sni",
            help="Filter by TLS SNI (match_phrase on zeek.ssl.server_name)",
        )
        parser.add_argument(
            "--invalid-only", dest="ssl_invalid_only", action="store_true",
            help="Show only records where zeek.ssl.validation_status is not 'ok'",
        )

    def describe_record(self, record: dict) -> str:
        sni = record.get("ssl_server_name", "") or record.get("dest_ip", "?")
        return (
            f"ssl {record.get('src_ip', '?')} → {sni}:{record.get('dest_port', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/ssl"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("SNI filter", new.get("ssl_sni"))
        new["ssl_sni"] = val if val else None
        raw = _ask("Invalid certs only (y/n)", "y" if new.get("ssl_invalid_only") else "n")
        new["ssl_invalid_only"] = raw.lower() in ("y", "yes")
