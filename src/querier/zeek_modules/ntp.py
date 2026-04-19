#!/usr/bin/env python3
"""Zeek NTP log module — time synchronisation and amplification detection."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class NtpModule(ZeekModule):
    DATASETS = ["ntp"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.ntp.version",
        "zeek.ntp.mode",
        "zeek.ntp.stratum",
        "zeek.ntp.poll",
        "zeek.ntp.precision",
        "zeek.ntp.root_delay",
        "zeek.ntp.root_disp",
        "zeek.ntp.ref_id",
        "zeek.ntp.org_time",
        "zeek.ntp.rec_time",
        "zeek.ntp.xmt_time",
        "network.community_id",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    WEB_CATEGORY = "network"
    WEB_COLUMNS = [
        ("Mode", lambda r: str(r.get("mode")) if r.get("mode") is not None else "—"),
        ("Version", lambda r: str(r.get("version")) if r.get("version") else "—"),
        ("Stratum", lambda r: str(r.get("stratum")) if r.get("stratum") is not None else "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Version", lambda r: str(r.get("version")) if r.get("version") else "—"),
        ("Mode", lambda r: str(r.get("mode")) if r.get("mode") is not None else "—"),
        ("Stratum", lambda r: str(r.get("stratum")) if r.get("stratum") is not None else "—"),
        ("Poll", lambda r: str(r.get("poll")) if r.get("poll") is not None else "—"),
        ("Ref ID", lambda r: r.get("ref_id", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zn = src.get("zeek", {}).get("ntp", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "version": zn.get("version"),
            "mode": zn.get("mode"),
            "stratum": zn.get("stratum"),
            "poll": zn.get("poll"),
            "ref_id": zn.get("ref_id", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("mode"),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("mode") is not None:
            try:
                clauses.append({"term": {"zeek.ntp.mode": int(search_params["mode"])}})
            except (ValueError, TypeError):
                console.print("[yellow]ntp: ignoring non-numeric mode value[/yellow]")
        if search_params.get("version") is not None:
            try:
                clauses.append({"term": {"zeek.ntp.version": int(search_params["version"])}})
            except (ValueError, TypeError):
                console.print("[yellow]ntp: ignoring non-numeric version value[/yellow]")

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique NTP record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP", style="yellow", no_wrap=True, max_width=36)
        table.add_column("Version", no_wrap=True)
        table.add_column("Mode", no_wrap=True)
        table.add_column("Stratum", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            flow = f"{src_ip} → {dest_ip}"
            version = str(rec.get("version")) if rec.get("version") is not None else "—"
            mode = str(rec.get("mode")) if rec.get("mode") is not None else "—"
            stratum = str(rec.get("stratum")) if rec.get("stratum") is not None else "—"

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                version,
                mode,
                stratum,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--mode",
            dest="mode",
            help="Filter by NTP mode (3=client, 4=server, 6=control, 7=private)",
        )
        parser.add_argument(
            "--version",
            dest="version",
            help="Filter by NTP version",
        )

    def describe_record(self, record: dict) -> str:
        mode = str(record.get("mode")) if record.get("mode") is not None else "?"
        return f"ntp {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [mode={mode}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/ntp"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Mode filter (3=client/4=server/6=control/7=private)", new.get("mode"))
        new["mode"] = val if val else None
        val = _ask("Version filter", new.get("version"))
        new["version"] = val if val else None
