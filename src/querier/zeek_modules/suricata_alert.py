#!/usr/bin/env python3
"""Suricata IDS alert module — signature-based detection records.

Queries event.dataset: alert with event.module: suricata. Supports filtering
by severity, SID, rule name/category, and tag. Use --no-stream or --severity 1
to skip protocol anomaly noise (~99.6% of records are severity 3).

Overrides fp_action to offer broad (IP-wide) or narrow (SID-scoped) suppression.
"""

from rich import box
from rich.table import Table

from .base import ZeekModule, _first, _sensor_str, console


class SuricataAlertModule(ZeekModule):
    WEB_CATEGORY = "alerts"
    WEB_ICON = "fa-shield-halved"
    EXTRA_PARAMS = ["rule_name", "rule_category", "severity", "sid", "exclude_stream", "tag"]
    SUMMARY_FIELD = "rule.name"
    SUMMARY_PARAM = "rule_name"
    DATASETS = ["alert"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "rule.name",
        "rule.id",
        "rule.category",
        "suricata.alert.severity",
        "suricata.alert.action",
        "network.transport",
        "network.application",
        "network.community_id",
        "network.direction",
        "event.module",
        "event.dataset",
        "tags",
        "destination.geo.country_name",
        "destination.as.full",
    ]

    WEB_COLUMNS = [
        ("Rule", lambda r: (r.get("rule_name", "") or "—")[:60]),
        ("Cat", lambda r: r.get("rule_category", "—") or "—"),
        ("Sev", lambda r: str(r.get("severity", "—"))),
    ]

    def build_extra_must(self, search_params: dict) -> tuple:
        """Return (must_clauses, post_filters).

        Always includes event.module: suricata. Adds optional severity, SID,
        rule_name, rule_category, tag filters.
        """
        must: list = [{"term": {"event.module": "suricata"}}]
        post_filters: list = []

        if search_params.get("severity") is not None:
            must.append({"term": {"suricata.alert.severity": int(search_params["severity"])}})
        if search_params.get("sid") is not None:
            must.append({"term": {"rule.id": int(search_params["sid"])}})
        if search_params.get("rule_name"):
            must.append({"wildcard": {"rule.name": f"*{search_params['rule_name']}*"}})
        if search_params.get("rule_category"):
            must.append({"term": {"rule.category": search_params["rule_category"]}})
        if search_params.get("tag"):
            must.append({"term": {"tags": search_params["tag"]}})
        if search_params.get("exclude_stream") in (True, "true", "on", "1"):
            must.append(
                {
                    "bool": {
                        "must_not": [
                            {"wildcard": {"rule.name": "SURICATA STREAM*"}},
                            {"wildcard": {"rule.name": "SURICATA QUIC*"}},
                        ]
                    }
                }
            )

        return must, post_filters

    def parse_hit(self, src: dict) -> dict:
        alert = src.get("suricata", {}).get("alert", {})
        rule = src.get("rule", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "rule_name": rule.get("name", ""),
            "sid": rule.get("id"),
            "rule_category": _first(rule.get("category", "")),
            "severity": alert.get("severity"),
            "action": alert.get("action", ""),
            "transport": src.get("network", {}).get("transport", ""),
            "app_proto": src.get("network", {}).get("application", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction": src.get("network", {}).get("direction", ""),
            "geo_country": (src.get("destination", {}).get("geo", {}).get("country_name", "")),
            "dest_asn": src.get("destination", {}).get("as", {}).get("full", ""),
            "tags": src.get("tags", []),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("sid", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Dst IP", lambda r: r.get("dest_ip", "—") or "—"),
        ("Rule Name", lambda r: r.get("rule_name", "—")),
        ("SID", lambda r: str(r.get("sid", "—"))),
        ("Category", lambda r: r.get("rule_category", "—") or "—"),
        ("Severity", lambda r: str(r.get("severity", "—"))),
        ("Action", lambda r: r.get("action", "—")),
        ("Transport", lambda r: r.get("transport", "—") or "—"),
        ("App Proto", lambda r: r.get("app_proto", "—") or "—"),
        ("Direction", lambda r: r.get("direction", "—") or "—"),
        ("Country", lambda r: r.get("geo_country", "—") or "—"),
        ("ASN", lambda r: r.get("dest_asn", "—") or "—"),
        ("Tags", lambda r: ", ".join(r.get("tags", [])) or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique alert(s)"
            f" across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Dst IP", no_wrap=True)
        table.add_column("Sev", justify="center", no_wrap=True)
        table.add_column("SID", no_wrap=True)
        table.add_column("Rule Name", max_width=40, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            sev = rec.get("severity")
            sev_style = {1: "bold red", 2: "yellow", 3: "dim"}.get(sev, "")
            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                rec.get("dest_ip", "") or "—",
                f"[{sev_style}]{sev}[/{sev_style}]" if sev_style else str(sev),
                str(rec.get("sid", "")),
                rec.get("rule_name", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--rule", dest="rule_name", help="Filter by rule name (wildcard)")
        parser.add_argument("--category", dest="rule_category", help="Filter by rule category")
        parser.add_argument(
            "--severity",
            type=int,
            choices=[1, 2, 3],
            help="Severity (1=high, 2=medium, 3=low)",
        )
        parser.add_argument("--sid", type=int, help="Filter by Suricata rule ID")
        parser.add_argument(
            "--no-stream",
            action="store_true",
            dest="exclude_stream",
            help="Exclude SURICATA STREAM/QUIC noise rules",
        )
        parser.add_argument("--tag", help="Filter by tag (e.g. CISA_KEV, Exploit)")

    def describe_record(self, record: dict) -> str:
        return (
            f"suricata {record.get('src_ip', '?')} "
            f"SID:{record.get('sid', '?')} "
            f"{(record.get('rule_name', '') or '?')[:60]}"
        )

    def fp_signature(self, record: dict) -> str:
        return record.get("rule_name") or f"SID:{record.get('sid', 'unknown')}"

    def fp_action(self, record: dict) -> None:
        """Offer broad (IP-wide) or narrow (SID-scoped) suppression."""
        console.print("\n[bold cyan]Suppress scope:[/bold cyan]")
        console.print("  [b]road  — suppress this IP across all tools → filters/ips/")
        console.print("  [n]arrow — suppress this SID from this IP → filters/suricata/")

        try:
            choice = input("  Choice [b/n]: ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            console.print("[dim]Cancelled.[/dim]")
            return

        if choice == "b":
            from src.querier.fp_manager import create_filter_interactive

            fp_alert = {
                "src_ip": record.get("src_ip"),
                "dest_ip": record.get("dest_ip"),
                "dest_port": record.get("dest_port"),
                "alert": {
                    "signature": self.fp_signature(record),
                    "severity": record.get("severity", 3),
                },
                "clientID": (record.get("sensors") or [record.get("sensor", "")])[0],
            }
            create_filter_interactive(alert=fp_alert)
        elif choice == "n":
            self._create_sid_filter(record)
        else:
            console.print("[dim]Skipped.[/dim]")

    def _create_sid_filter(self, record: dict) -> None:
        """Create a narrow SID+IP filter in filters/suricata/false_positives.yaml."""
        from src.querier.fp_manager import (
            append_clauses_to_file,
            ensure_subcategory,
            filter_file_path,
        )

        src_ip = record.get("src_ip", "")
        sid = record.get("sid")

        if not src_ip or not sid:
            console.print("[red]Missing src_ip or SID — cannot create filter.[/red]")
            return

        clause: dict = {
            "bool": {
                "must": [
                    {"term": {"src_ip": src_ip}},
                    {"term": {"rule.id": sid}},
                ]
            }
        }

        comment = input("Comment (optional): ").strip()
        if comment:
            clause["comment"] = comment

        fpath = filter_file_path("suricata", "false_positives")
        append_clauses_to_file(fpath, [clause], author="analyst")
        ensure_subcategory("suricata", "false_positives")
        console.print(f"[green]Written: {fpath}[/green]")

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        new["rule_name"] = _ask("Rule name filter (wildcard)", new.get("rule_name")) or None
        new["rule_category"] = _ask("Category filter", new.get("rule_category")) or None
        val = _ask(
            "Severity (1/2/3)",
            str(new["severity"]) if new.get("severity") else "",
        )
        new["severity"] = int(val) if val else None
        val = _ask("SID", str(new["sid"]) if new.get("sid") else "")
        new["sid"] = int(val) if val else None
