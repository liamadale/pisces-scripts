#!/usr/bin/env python3
"""Zeek http log module — HTTP request/response records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _fmt_bytes, _sensor_str, console


class HttpModule(ZeekModule):
    DATASETS = ["http"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.http.method",
        "zeek.http.host",
        "zeek.http.uri",
        "zeek.http.user_agent",
        "zeek.http.status_code",
        "zeek.http.request_body_len",
        "zeek.http.response_body_len",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("http_method"):
            clauses.append({"term": {"zeek.http.method": search_params["http_method"]}})
        if search_params.get("http_host"):
            clauses.append({"match_phrase": {"zeek.http.host": search_params["http_host"]}})
        if search_params.get("status_code") is not None:
            clauses.append({"term": {"zeek.http.status_code": search_params["status_code"]}})
        if search_params.get("http_uri"):
            clauses.append({"match_phrase": {"zeek.http.uri": search_params["http_uri"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        http = src.get("zeek", {}).get("http", {})
        return {
            "timestamp":       src.get("@timestamp", ""),
            "sensor":          src.get("host", {}).get("name", ""),
            "log_type":        src.get("event", {}).get("dataset", ""),
            "src_ip":          src.get("source", {}).get("ip", ""),
            "src_port":        src.get("source", {}).get("port"),
            "dest_ip":         src.get("destination", {}).get("ip", ""),
            "dest_port":       src.get("destination", {}).get("port"),
            "http_method":     http.get("method", ""),
            "http_host":       http.get("host", ""),
            "http_uri":        http.get("uri", ""),
            "http_user_agent": http.get("user_agent", ""),
            "http_status":     http.get("status_code"),
            "http_req_bytes":  http.get("request_body_len"),
            "http_resp_bytes": http.get("response_body_len"),
            "_raw":            src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("http_host", ""),
            record.get("http_method", ""),
            record.get("http_uri", ""),
        )

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique HTTP request(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Method", no_wrap=True)
        table.add_column("Host", no_wrap=True)
        table.add_column("URI", no_wrap=True)
        table.add_column("Status", justify="right", no_wrap=True)
        table.add_column("Req", justify="right", no_wrap=True)
        table.add_column("Resp", justify="right", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            status = rec.get("http_status")
            table.add_row(
                str(idx),
                rec["timestamp"][:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("src_ip", ""),
                rec.get("http_method", "") or "—",
                rec.get("http_host", "") or "—",
                rec.get("http_uri", "") or "—",
                str(status) if status is not None else "—",
                _fmt_bytes(rec.get("http_req_bytes")),
                _fmt_bytes(rec.get("http_resp_bytes")),
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--method", dest="http_method",
            help="Filter by HTTP method (term on zeek.http.method, e.g. POST)",
        )
        parser.add_argument(
            "--host", dest="http_host",
            help="Filter by HTTP host (match_phrase on zeek.http.host)",
        )
        parser.add_argument(
            "--status-code", type=int, dest="status_code",
            help="Filter by HTTP status code (term on zeek.http.status_code)",
        )
        parser.add_argument(
            "--uri", dest="http_uri",
            help="Filter by HTTP URI (match_phrase on zeek.http.uri)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"http {record.get('src_ip', '?')} "
            f"{record.get('http_method', '?')} "
            f"{record.get('http_host', '?')}{record.get('http_uri', '/')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/http"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("HTTP method filter", new.get("http_method"))
        new["http_method"] = val if val else None
        val = _ask("HTTP host filter", new.get("http_host"))
        new["http_host"] = val if val else None
        val = _ask("HTTP URI filter", new.get("http_uri"))
        new["http_uri"] = val if val else None
        val = _ask("Status code filter", new.get("status_code"))
        if val:
            try:
                new["status_code"] = int(val)
            except ValueError:
                new["status_code"] = None
        else:
            new["status_code"] = None
