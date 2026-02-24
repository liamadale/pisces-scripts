#!/usr/bin/env python3
"""Zeek notice log module — Zeek notice framework alert records.

Overrides fp_action to offer broad (IP-wide) or narrow (IP + notice.note)
suppression scope.
"""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class NoticeModule(ZeekModule):
    DATASETS = ["notice"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.notice.note",
        "zeek.notice.msg",
        "zeek.notice.sub",
        "zeek.notice.actions",
        "zeek.notice.dropped",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("notice_note"):
            clauses.append({"term": {"zeek.notice.note": search_params["notice_note"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        notice = src.get("zeek", {}).get("notice", {})
        return {
            "timestamp":    src.get("@timestamp", ""),
            "sensor":       src.get("host", {}).get("name", ""),
            "log_type":     src.get("event", {}).get("dataset", ""),
            "src_ip":       src.get("source", {}).get("ip", ""),
            "src_port":     src.get("source", {}).get("port"),
            "dest_ip":      src.get("destination", {}).get("ip", ""),
            "dest_port":    src.get("destination", {}).get("port"),
            "notice_note":  notice.get("note", ""),
            "notice_msg":   notice.get("msg", ""),
            "notice_sub":   notice.get("sub", ""),
            "notice_actions": notice.get("actions", ""),
            "notice_dropped": notice.get("dropped"),
            "_raw":         src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("notice_note", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique notice(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("→", justify="center", width=1, no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Note Type", no_wrap=True)
        table.add_column("Message", no_wrap=True)
        table.add_column("Sub", no_wrap=True)
        table.add_column("Dropped", justify="center", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            dropped = rec.get("notice_dropped")
            dropped_str = "✓" if dropped is True else ("✗" if dropped is False else "—")
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                "→",
                rec.get("dest_ip", "") or "—",
                rec.get("notice_note", "") or "—",
                rec.get("notice_msg", "") or "—",
                rec.get("notice_sub", "") or "—",
                dropped_str,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--note", dest="notice_note",
            help="Filter by notice type (term on zeek.notice.note, e.g. SSH::Password_Guessing)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"notice {record.get('src_ip', '?')} "
            f"{record.get('notice_note', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return record.get("notice_note") or "zeek/notice"

    def fp_action(self, record: dict) -> None:
        """Offer broad (IP-wide) or narrow (IP + notice.note) suppression scope."""
        console.print("\n[bold cyan]Suppress scope:[/bold cyan]")
        console.print(
            "  [b]road  — suppress this IP across all tools → filters/ips/ (existing flow)"
        )
        console.print(
            "  [n]arrow — suppress this notice type from this IP → filters/notices/"
        )

        try:
            choice = input("  Choice [b/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("[dim]Cancelled.[/dim]")
            return

        if choice == "b":
            from src.querier.fp_manager import create_filter_interactive
            fp_alert = {
                "src_ip":    record.get("src_ip"),
                "dest_ip":   record.get("dest_ip"),
                "dest_port": record.get("dest_port"),
                "alert": {
                    "signature": self.fp_signature(record),
                    "severity":  3,
                },
                "clientID": (record.get("sensors") or [record.get("sensor", "")])[0],
            }
            create_filter_interactive(alert=fp_alert)
        elif choice == "n":
            from src.querier.fp_manager import create_notice_filter_interactive
            create_notice_filter_interactive(record)
        else:
            console.print("[dim]Skipped.[/dim]")

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Notice note filter (e.g. SSH::Password_Guessing)", new.get("notice_note"))
        new["notice_note"] = val if val else None
