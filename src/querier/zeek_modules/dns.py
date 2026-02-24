#!/usr/bin/env python3
"""Zeek dns log module — DNS query records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class DnsModule(ZeekModule):
    DATASETS = ["dns"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "destination.ip",
        "destination.port",
        "network.transport",
        "zeek.dns.query",
        "zeek.dns.qtype_name",
        "zeek.dns.rcode_name",
        "zeek.dns.answers",
        "zeek.dns.rtt",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("dns_query"):
            clauses.append({"match_phrase": {"zeek.dns.query": search_params["dns_query"]}})
        if search_params.get("rcode"):
            clauses.append({"term": {"zeek.dns.rcode_name": search_params["rcode"]}})
        if search_params.get("qtype"):
            clauses.append({"term": {"zeek.dns.qtype_name": search_params["qtype"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        dns = src.get("zeek", {}).get("dns", {})
        answers = dns.get("answers", [])
        if isinstance(answers, list):
            answers_str = ", ".join(str(a) for a in answers)
        else:
            answers_str = str(answers) if answers else ""
        return {
            "timestamp":  src.get("@timestamp", ""),
            "sensor":     src.get("host", {}).get("name", ""),
            "log_type":   src.get("event", {}).get("dataset", ""),
            "src_ip":     src.get("source", {}).get("ip", ""),
            "src_port":   src.get("source", {}).get("port"),
            "dest_ip":    src.get("destination", {}).get("ip", ""),
            "dest_port":  src.get("destination", {}).get("port"),
            "query":      dns.get("query", ""),
            "qtype":      dns.get("qtype_name", ""),
            "rcode":      dns.get("rcode_name", ""),
            "answers":    answers_str,
            "rtt":        dns.get("rtt"),
            "_raw":       src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("query", ""),
            record.get("qtype", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique DNS query(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Resolver", style="dim", no_wrap=True)
        table.add_column("Query", no_wrap=True)
        table.add_column("Type", no_wrap=True)
        table.add_column("RCode", no_wrap=True)
        table.add_column("Answers", no_wrap=True)
        table.add_column("RTT", justify="right", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            rtt = rec.get("rtt")
            rtt_str = f"{float(rtt) * 1000:.1f}ms" if rtt is not None else "—"
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                "→",
                rec.get("dest_ip", "") or "—",
                rec.get("query", "") or "—",
                rec.get("qtype", "") or "—",
                rec.get("rcode", "") or "—",
                rec.get("answers", "") or "—",
                rtt_str,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--query", dest="dns_query",
            help="Filter by DNS query (match_phrase on zeek.dns.query)",
        )
        parser.add_argument(
            "--rcode",
            help="Filter by response code (term on zeek.dns.rcode_name, e.g. NXDOMAIN)",
        )
        parser.add_argument(
            "--qtype",
            help="Filter by query type (term on zeek.dns.qtype_name, e.g. TXT)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"dns {record.get('src_ip', '?')} → "
            f"{record.get('query', '?')} ({record.get('qtype', '?')})"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/dns"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("DNS query filter", new.get("dns_query"))
        new["dns_query"] = val if val else None
        val = _ask("RCode filter (e.g. NXDOMAIN)", new.get("rcode"))
        new["rcode"] = val if val else None
        val = _ask("QType filter (e.g. TXT)", new.get("qtype"))
        new["qtype"] = val if val else None
