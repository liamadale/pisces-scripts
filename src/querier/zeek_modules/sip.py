#!/usr/bin/env python3
"""Zeek sip log module — SIP/VoIP session records."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _sensor_str, console


class SipModule(ZeekModule):
    DATASETS = ["sip"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.sip.method",
        "zeek.sip.uri",
        "zeek.sip.date",
        "zeek.sip.request_from",
        "zeek.sip.request_to",
        "zeek.sip.response_from",
        "zeek.sip.response_to",
        "zeek.sip.reply_to",
        "zeek.sip.call_id",
        "zeek.sip.seq",
        "zeek.sip.subject",
        "zeek.sip.user_agent",
        "zeek.sip.status_code",
        "zeek.sip.status_msg",
        "zeek.sip.warning",
        "zeek.sip.content_type",
        "network.community_id",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    WEB_CATEGORY = "infrastructure"
    WEB_COLUMNS = [
        ("Method", lambda r: r.get("method", "—") or "—"),
        ("URI", lambda r: r.get("uri", "—") or "—"),
        (
            "Status",
            lambda r: str(r.get("status_code")) if r.get("status_code") is not None else "—",
        ),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Method", lambda r: r.get("method", "—")),
        ("URI", lambda r: r.get("uri", "—") or "—"),
        ("From", lambda r: r.get("request_from", "—") or "—"),
        ("To", lambda r: r.get("request_to", "—") or "—"),
        ("Call ID", lambda r: r.get("call_id", "—") or "—"),
        ("User-Agent", lambda r: r.get("user_agent", "—") or "—"),
        (
            "Status Code",
            lambda r: str(r.get("status_code")) if r.get("status_code") is not None else "—",
        ),
        ("Status Msg", lambda r: r.get("status_msg", "—") or "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zs = src.get("zeek", {}).get("sip", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "method": zs.get("method", ""),
            "uri": zs.get("uri", ""),
            "request_from": zs.get("request_from", ""),
            "request_to": zs.get("request_to", ""),
            "call_id": zs.get("call_id", ""),
            "user_agent": zs.get("user_agent", ""),
            "status_code": zs.get("status_code"),
            "status_msg": zs.get("status_msg", ""),
            "community_id": src.get("network", {}).get("community_id", ""),
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("method", ""),
            record.get("status_code"),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("method"):
            clauses.append({"term": {"zeek.sip.method": search_params["method"]}})
        if search_params.get("status_code"):
            clauses.append({"term": {"zeek.sip.status_code": search_params["status_code"]}})
        if search_params.get("user_agent"):
            clauses.append({"match_phrase": {"zeek.sip.user_agent": search_params["user_agent"]}})

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SIP session record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP", style="yellow", no_wrap=True, max_width=36)
        table.add_column("Method", no_wrap=True)
        table.add_column("URI", no_wrap=True, max_width=28, overflow="ellipsis")
        table.add_column("Status", justify="right", no_wrap=True)
        table.add_column("User-Agent", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            flow = f"{src_ip} → {dest_ip}"

            status = rec.get("status_code")
            status_str = str(status) if status is not None else "—"

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                rec.get("method", "") or "—",
                rec.get("uri", "") or "—",
                status_str,
                rec.get("user_agent", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--method",
            dest="method",
            help="Filter by SIP method (INVITE, REGISTER, OPTIONS, etc.)",
        )
        parser.add_argument(
            "--status-code", dest="status_code", help="Filter by SIP status code (exact match)"
        )
        parser.add_argument(
            "--user-agent", dest="user_agent", help="Filter by User-Agent (match_phrase)"
        )

    def describe_record(self, record: dict) -> str:
        method = record.get("method") or "?"
        uri = record.get("uri") or "?"
        return f"sip {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{method} {uri}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/sip"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Method filter (INVITE/REGISTER/OPTIONS)", new.get("method"))
        new["method"] = val if val else None
        val = _ask("Status code filter", new.get("status_code"))
        new["status_code"] = val if val else None
        val = _ask("User-Agent filter", new.get("user_agent"))
        new["user_agent"] = val if val else None
