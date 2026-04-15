#!/usr/bin/env python3
"""Zeek capture_loss log module — packet capture loss diagnostics."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _fmt_dur, _sensor_str, console


class CaptureLossModule(ZeekModule):
    DATASETS = ["capture_loss"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "zeek.capture_loss.ts_delta",
        "zeek.capture_loss.peer",
        "zeek.capture_loss.gaps",
        "zeek.capture_loss.acks",
        "zeek.capture_loss.percent_lost",
        "event.dataset",
    ]

    # Diagnostic module — no IPs, no hashes, no enrichment, no FP filters.
    SUPPORTS_IP_FILTER = False
    SUPPORTS_ENRICHMENT = False
    SUPPORTS_FP = False

    WEB_CATEGORY = "diagnostic"
    WEB_COLUMNS = [
        ("Peer", lambda r: r.get("peer", "—") or "—"),
        (
            "% Lost",
            lambda r: (
                f"{r.get('percent_lost', 0):.1f}%" if r.get("percent_lost") is not None else "—"
            ),
        ),
        ("Gaps", lambda r: str(r.get("gaps")) if r.get("gaps") is not None else "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Peer", lambda r: r.get("peer", "—")),
        ("Gaps", lambda r: str(r.get("gaps")) if r.get("gaps") is not None else "—"),
        ("ACKs", lambda r: str(r.get("acks")) if r.get("acks") is not None else "—"),
        (
            "% Lost",
            lambda r: (
                f"{r.get('percent_lost', 0):.2f}%" if r.get("percent_lost") is not None else "—"
            ),
        ),
        ("Δt", lambda r: _fmt_dur(r.get("ts_delta"))),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zcl = src.get("zeek", {}).get("capture_loss", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "peer": zcl.get("peer", ""),
            "gaps": zcl.get("gaps"),
            "acks": zcl.get("acks"),
            "percent_lost": zcl.get("percent_lost"),
            "ts_delta": zcl.get("ts_delta"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("sensor", ""),
            record.get("peer", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique capture loss record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Peer", no_wrap=True)
        table.add_column("Gaps", justify="right", no_wrap=True)
        table.add_column("ACKs", justify="right", no_wrap=True)
        table.add_column("% Lost", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            pct = rec.get("percent_lost")
            pct_str = f"{pct:.2f}%" if pct is not None else "—"

            if pct is not None and pct > 20:
                pct_col = f"[red]{pct_str}[/red]"
            elif pct is not None and pct > 5:
                pct_col = f"[yellow]{pct_str}[/yellow]"
            else:
                pct_col = pct_str

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("peer", "") or "—",
                str(rec.get("gaps")) if rec.get("gaps") is not None else "—",
                str(rec.get("acks")) if rec.get("acks") is not None else "—",
                pct_col,
            )

        console.print(table)

    def describe_record(self, record: dict) -> str:
        return f"capture_loss sensor={record.get('sensor', '?')} peer={record.get('peer', '?')}"

    def fp_signature(self, record: dict) -> str:
        return "zeek/capture_loss"
