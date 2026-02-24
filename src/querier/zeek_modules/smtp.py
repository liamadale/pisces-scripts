#!/usr/bin/env python3
"""Zeek smtp log module — SMTP email session records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class SmtpModule(ZeekModule):
    DATASETS = ["smtp"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.smtp.mailfrom",
        "zeek.smtp.rcptto",
        "zeek.smtp.from",
        "zeek.smtp.subject",
        "zeek.smtp.helo",
        "zeek.smtp.last_reply",
        "zeek.smtp.tls",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("smtp_mail_from"):
            clauses.append({"match_phrase": {"zeek.smtp.mailfrom": search_params["smtp_mail_from"]}})
        if search_params.get("smtp_rcpt_to"):
            clauses.append({"match_phrase": {"zeek.smtp.rcptto": search_params["smtp_rcpt_to"]}})
        if search_params.get("smtp_subject"):
            clauses.append({"match_phrase": {"zeek.smtp.subject": search_params["smtp_subject"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        smtp = src.get("zeek", {}).get("smtp", {})
        rcptto = smtp.get("rcptto", [])
        if isinstance(rcptto, list):
            rcptto_str = ", ".join(str(r) for r in rcptto)
        else:
            rcptto_str = str(rcptto) if rcptto else ""
        return {
            "timestamp":    src.get("@timestamp", ""),
            "sensor":       src.get("host", {}).get("name", ""),
            "log_type":     src.get("event", {}).get("dataset", ""),
            "src_ip":       src.get("source", {}).get("ip", ""),
            "src_port":     src.get("source", {}).get("port"),
            "dest_ip":      src.get("destination", {}).get("ip", ""),
            "dest_port":    src.get("destination", {}).get("port"),
            "smtp_mailfrom": smtp.get("mailfrom", ""),
            "smtp_rcptto":  rcptto_str,
            "smtp_from":    smtp.get("from", ""),
            "smtp_subject": smtp.get("subject", ""),
            "smtp_helo":    smtp.get("helo", ""),
            "smtp_last_reply": smtp.get("last_reply", ""),
            "smtp_tls":     smtp.get("tls"),
            "_raw":         src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("smtp_mailfrom", ""),
            record.get("smtp_rcptto", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SMTP session(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Helo", no_wrap=True)
        table.add_column("Mail From", no_wrap=True)
        table.add_column("Rcpt To", no_wrap=True)
        table.add_column("Subject", no_wrap=True)
        table.add_column("TLS", justify="center", no_wrap=True)
        table.add_column("Last Reply", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            tls = rec.get("smtp_tls")
            tls_str = "✓" if tls is True else ("✗" if tls is False else "—")
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                "→",
                rec.get("dest_ip", ""),
                rec.get("smtp_helo", "") or "—",
                rec.get("smtp_mailfrom", "") or "—",
                rec.get("smtp_rcptto", "") or "—",
                rec.get("smtp_subject", "") or "—",
                tls_str,
                rec.get("smtp_last_reply", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--mail-from", dest="smtp_mail_from",
            help="Filter by MAIL FROM address (match_phrase on zeek.smtp.mailfrom)",
        )
        parser.add_argument(
            "--rcpt-to", dest="smtp_rcpt_to",
            help="Filter by RCPT TO address (match_phrase on zeek.smtp.rcptto)",
        )
        parser.add_argument(
            "--subject", dest="smtp_subject",
            help="Filter by email subject (match_phrase on zeek.smtp.subject)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"smtp {record.get('src_ip', '?')} "
            f"{record.get('smtp_mailfrom', '?')} → {record.get('smtp_rcptto', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/smtp"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Mail From filter", new.get("smtp_mail_from"))
        new["smtp_mail_from"] = val if val else None
        val = _ask("Rcpt To filter", new.get("smtp_rcpt_to"))
        new["smtp_rcpt_to"] = val if val else None
        val = _ask("Subject filter", new.get("smtp_subject"))
        new["smtp_subject"] = val if val else None
