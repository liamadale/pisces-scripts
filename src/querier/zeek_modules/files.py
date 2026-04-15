#!/usr/bin/env python3
"""Zeek files log module — file extraction and transfer metadata."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _fmt_bytes, _sensor_str, console, is_private


class FilesModule(ZeekModule):
    DATASETS = ["files"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "zeek.files.fuid",
        "zeek.files.tx_hosts",
        "zeek.files.rx_hosts",
        "zeek.files.source",
        "zeek.files.depth",
        "zeek.files.analyzers",
        "zeek.files.mime_type",
        "zeek.files.filename",
        "zeek.files.duration",
        "zeek.files.total_bytes",
        "zeek.files.missing_bytes",
        "zeek.files.overflow_bytes",
        "zeek.files.md5",
        "zeek.files.sha1",
        "zeek.files.sha256",
        "zeek.files.extracted",
        "zeek.files.extracted_cutoff",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    # source.ip is NOT in SOURCE_FIELDS — IPs come from tx_hosts/rx_hosts arrays.
    # run_query() guards src_ip_filter against modules without source.ip.
    SUPPORTS_IP_FILTER = True  # post-filters handle it

    WEB_CATEGORY = "files"
    WEB_COLUMNS = [
        ("MIME", lambda r: r.get("mime_type", "—") or "—"),
        ("SHA256", lambda r: ((r.get("sha256", "") or "")[:12] + "…") if r.get("sha256") else "—"),
        ("Extr", lambda r: "✓" if r.get("extracted") else "✗"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("FUID", lambda r: r.get("fuid", "—")),
        ("Proto", lambda r: r.get("source_proto", "—")),
        ("MIME Type", lambda r: r.get("mime_type", "—")),
        ("Filename", lambda r: r.get("filename", "—") or "—"),
        ("Size", lambda r: _fmt_bytes(r.get("total_bytes"))),
        ("MD5", lambda r: r.get("md5", "—") or "—"),
        ("SHA1", lambda r: r.get("sha1", "—") or "—"),
        ("SHA256", lambda r: r.get("sha256", "—") or "—"),
        ("Extracted", lambda r: "✓" if r.get("extracted") else "✗"),
        ("Analyzers", lambda r: ", ".join(r.get("analyzers") or []) or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zf = src.get("zeek", {}).get("files", {})
        tx_hosts = zf.get("tx_hosts") or []
        rx_hosts = zf.get("rx_hosts") or []
        src_ip = tx_hosts[0] if tx_hosts else ""
        dest_ip = rx_hosts[0] if rx_hosts else ""
        analyzers = zf.get("analyzers")
        if isinstance(analyzers, str):
            analyzers = [analyzers]
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "fuid": zf.get("fuid", ""),
            "source_proto": zf.get("source", ""),
            "mime_type": zf.get("mime_type", ""),
            "filename": zf.get("filename", ""),
            "total_bytes": zf.get("total_bytes"),
            "md5": zf.get("md5", ""),
            "sha1": zf.get("sha1", ""),
            "sha256": zf.get("sha256", ""),
            "extracted": zf.get("extracted"),
            "analyzers": analyzers or [],
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("sha256") or record.get("md5") or "",
            record.get("mime_type", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("mime"):
            clauses.append({"match_phrase": {"zeek.files.mime_type": search_params["mime"]}})
        if search_params.get("hash"):
            h = search_params["hash"]
            field = {32: "zeek.files.md5", 40: "zeek.files.sha1", 64: "zeek.files.sha256"}.get(
                len(h)
            )
            if field:
                clauses.append({"term": {field: h}})
        if search_params.get("source_proto"):
            clauses.append({"term": {"zeek.files.source": search_params["source_proto"]}})

        if search_params.get("extracted_only"):
            post_filters.append(lambda r: r.get("extracted") is True)
        if search_params.get("public_only"):
            post_filters.append(lambda r: not is_private(r.get("src_ip", "")))
        if search_params.get("src_ip"):
            ip = search_params["src_ip"]
            post_filters.append(lambda r, _ip=ip: r.get("src_ip") == _ip)
        if search_params.get("dest_ip"):
            ip = search_params["dest_ip"]
            post_filters.append(lambda r, _ip=ip: r.get("dest_ip") == _ip)

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique file transfer(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP", style="yellow", no_wrap=True, max_width=36)
        table.add_column("Proto", no_wrap=True)
        table.add_column("MIME type", no_wrap=True, max_width=28, overflow="ellipsis")
        table.add_column("Filename", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Size", justify="right", no_wrap=True)
        table.add_column("SHA256", no_wrap=True)
        table.add_column("Extr?", justify="center", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            flow = f"{src_ip} → {dest_ip}"
            sha256 = rec.get("sha256", "") or ""
            sha256_short = (sha256[:12] + "…") if sha256 else "—"
            mime = rec.get("mime_type", "") or "—"
            extracted = rec.get("extracted")
            extr_str = "✓" if extracted else "✗"

            # Colour MIME types
            if mime in ("application/x-executable", "application/x-dosexec"):
                mime_str = f"[red]{mime}[/red]"
            elif mime.startswith("text/"):
                mime_str = f"[dim]{mime}[/dim]"
            else:
                mime_str = mime

            extr_col = f"[green]{extr_str}[/green]" if extracted else extr_str

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                rec.get("source_proto", "") or "—",
                mime_str,
                rec.get("filename", "") or "—",
                _fmt_bytes(rec.get("total_bytes")),
                sha256_short,
                extr_col,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--mime", dest="mime", help="Filter by MIME type")
        parser.add_argument(
            "--hash",
            dest="hash",
            help="Filter by MD5/SHA1/SHA256 (auto-detected by length)",
        )
        parser.add_argument(
            "--source-proto",
            dest="source_proto",
            help="Filter by originating protocol (HTTP, SMB, FTP, SMTP)",
        )
        parser.add_argument(
            "--extracted-only",
            dest="extracted_only",
            action="store_true",
            help="Show only files that were extracted to disk",
        )

    def describe_record(self, record: dict) -> str:
        name = record.get("filename") or record.get("mime_type") or "?"
        return f"files {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{name}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/files"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("MIME type filter", new.get("mime"))
        new["mime"] = val if val else None
        val = _ask("Hash filter (MD5/SHA1/SHA256)", new.get("hash"))
        new["hash"] = val if val else None
        val = _ask("Source protocol (HTTP/SMB/FTP/SMTP)", new.get("source_proto"))
        new["source_proto"] = val if val else None
        raw = _ask("Extracted only (y/n)", "y" if new.get("extracted_only") else "n")
        new["extracted_only"] = raw.lower() in ("y", "yes")
        val = _ask("Dest IP filter (blank to clear)", new.get("dest_ip"))
        new["dest_ip"] = val if val else None
