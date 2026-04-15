#!/usr/bin/env python3
"""Zeek PE log module — Windows PE binary metadata with hash enrichment via fuid→files pivot."""

import threading

from rich import box
from rich.table import Table

from .base import INDEX, ZeekModule, _sensor_str, console, query_opensearch

_tl = threading.local()

_CHUNK_SIZE = 1_000


class PEModule(ZeekModule):
    DATASETS = ["pe"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "zeek.pe.client",
        "zeek.pe.compile_ts",
        "zeek.pe.os",
        "zeek.pe.subsystem",
        "zeek.pe.is_exe",
        "zeek.pe.is_64bit",
        "zeek.pe.uses_aslr",
        "zeek.pe.uses_dep",
        "zeek.pe.uses_code_integrity",
        "zeek.pe.uses_seh",
        "zeek.pe.has_import_table",
        "zeek.pe.has_export_table",
        "zeek.pe.has_debug_data",
        "zeek.pe.section_names",
        "event.dataset",
        "event.risk_score",
        "event.risk_score_norm",
    ]

    # PE records have no IP addresses — metadata-only module.
    SUPPORTS_IP_FILTER = False
    SUPPORTS_ENRICHMENT = True  # hash-based VirusTotal enrichment via fuid→files pivot
    SUPPORTS_FP = True

    WEB_CATEGORY = "files"
    WEB_COLUMNS = [
        ("OS", lambda r: r.get("os", "—") or "—"),
        ("Subsystem", lambda r: r.get("subsystem", "—") or "—"),
        (
            "ASLR",
            lambda r: "✓" if r.get("uses_aslr") else ("✗" if r.get("uses_aslr") is False else "—"),
        ),
        (
            "DEP",
            lambda r: "✓" if r.get("uses_dep") else ("✗" if r.get("uses_dep") is False else "—"),
        ),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("FUID", lambda r: r.get("fuid", "—")),
        ("File Hash", lambda r: r.get("file_hash", "—") or "—"),
        ("Compile Time", lambda r: r.get("compile_ts", "—") or "—"),
        ("OS", lambda r: r.get("os", "—") or "—"),
        ("Subsystem", lambda r: r.get("subsystem", "—") or "—"),
        (
            "Is EXE",
            lambda r: "✓" if r.get("is_exe") else ("✗" if r.get("is_exe") is False else "—"),
        ),
        (
            "64-bit",
            lambda r: "✓" if r.get("is_64bit") else ("✗" if r.get("is_64bit") is False else "—"),
        ),
        (
            "ASLR",
            lambda r: "✓" if r.get("uses_aslr") else ("✗" if r.get("uses_aslr") is False else "—"),
        ),
        (
            "DEP",
            lambda r: "✓" if r.get("uses_dep") else ("✗" if r.get("uses_dep") is False else "—"),
        ),
        (
            "Code Integrity",
            lambda r: (
                "✓"
                if r.get("uses_code_integrity")
                else ("✗" if r.get("uses_code_integrity") is False else "—")
            ),
        ),
        (
            "SEH",
            lambda r: "✓" if r.get("uses_seh") else ("✗" if r.get("uses_seh") is False else "—"),
        ),
        (
            "Import Table",
            lambda r: (
                "✓"
                if r.get("has_import_table")
                else ("✗" if r.get("has_import_table") is False else "—")
            ),
        ),
        (
            "Export Table",
            lambda r: (
                "✓"
                if r.get("has_export_table")
                else ("✗" if r.get("has_export_table") is False else "—")
            ),
        ),
        (
            "Debug Data",
            lambda r: (
                "✓"
                if r.get("has_debug_data")
                else ("✗" if r.get("has_debug_data") is False else "—")
            ),
        ),
        ("Sections", lambda r: ", ".join(r.get("section_names") or []) or "—"),
        ("Risk Score", lambda r: str(r.get("risk_score")) if r.get("risk_score") else "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def prepare_hits(self, hits: list) -> None:
        """Batch-fetch file hashes from the files log via fuid → sha256/md5 lookup."""
        fuids = list(
            {
                hit["_source"].get("zeek", {}).get("pe", {}).get("client")
                for hit in hits
                if hit["_source"].get("zeek", {}).get("pe", {}).get("client")
            }
        )
        cache: dict = {}

        for i in range(0, len(fuids), _CHUNK_SIZE):
            chunk = fuids[i : i + _CHUNK_SIZE]
            body = {
                "size": len(chunk),
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"event.dataset": "files"}},
                            {"terms": {"zeek.files.fuid": chunk}},
                        ]
                    }
                },
                "_source": ["zeek.files.fuid", "zeek.files.sha256", "zeek.files.md5"],
            }
            params = {"path": f"{INDEX}/_search", "method": "POST"}
            raw = query_opensearch(body, params)
            if raw is None:
                continue
            for h in raw.get("hits", {}).get("hits", []):
                s = h.get("_source", {}).get("zeek", {}).get("files", {})
                fuid = s.get("fuid")
                if fuid and fuid not in cache:
                    cache[fuid] = s.get("sha256") or s.get("md5") or None

        _tl.fuid_hash_cache = cache

    def parse_hit(self, src: dict) -> dict:
        zp = src.get("zeek", {}).get("pe", {})
        fuid = zp.get("client", "")

        cache = getattr(_tl, "fuid_hash_cache", {})
        file_hash = cache.get(fuid)

        section_names = zp.get("section_names")
        if isinstance(section_names, str):
            section_names = [section_names]

        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "fuid": fuid,
            "file_hash": file_hash,
            "compile_ts": zp.get("compile_ts", ""),
            "os": zp.get("os", ""),
            "subsystem": zp.get("subsystem", ""),
            "is_exe": zp.get("is_exe"),
            "is_64bit": zp.get("is_64bit"),
            "uses_aslr": zp.get("uses_aslr"),
            "uses_dep": zp.get("uses_dep"),
            "uses_code_integrity": zp.get("uses_code_integrity"),
            "uses_seh": zp.get("uses_seh"),
            "has_import_table": zp.get("has_import_table"),
            "has_export_table": zp.get("has_export_table"),
            "has_debug_data": zp.get("has_debug_data"),
            "section_names": section_names or [],
            "risk_score": src.get("event", {}).get("risk_score"),
            "risk_score_norm": src.get("event", {}).get("risk_score_norm"),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("compile_ts", ""),
            record.get("os", ""),
            record.get("subsystem", ""),
            record.get("is_exe"),
            record.get("is_64bit"),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("no_aslr"):
            post_filters.append(lambda r: r.get("uses_aslr") is False)
        if search_params.get("no_dep"):
            post_filters.append(lambda r: r.get("uses_dep") is False)
        if search_params.get("only_32bit"):
            post_filters.append(lambda r: r.get("is_64bit") is False)

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique PE binary profile(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("FUID", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Compile Time", no_wrap=True)
        table.add_column("OS", no_wrap=True)
        table.add_column("Subsystem", no_wrap=True)
        table.add_column("64bit", justify="center", no_wrap=True)
        table.add_column("ASLR", justify="center", no_wrap=True)
        table.add_column("DEP", justify="center", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            is_64bit = rec.get("is_64bit")
            uses_aslr = rec.get("uses_aslr")
            uses_dep = rec.get("uses_dep")

            bit_str = "✓" if is_64bit else "✗" if is_64bit is False else "—"
            aslr_str = "✓" if uses_aslr else "✗" if uses_aslr is False else "—"
            dep_str = "✓" if uses_dep else "✗" if uses_dep is False else "—"

            # Flag missing mitigations in yellow
            aslr_col = f"[yellow]{aslr_str}[/yellow]" if uses_aslr is False else aslr_str
            dep_col = f"[yellow]{dep_str}[/yellow]" if uses_dep is False else dep_str

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                rec.get("fuid", "") or "—",
                (rec.get("compile_ts", "") or "")[:16].replace("T", " ") or "—",
                rec.get("os", "") or "—",
                rec.get("subsystem", "") or "—",
                bit_str,
                aslr_col,
                dep_col,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--no-aslr",
            dest="no_aslr",
            action="store_true",
            default=False,
            help="Show only PE binaries without ASLR",
        )
        parser.add_argument(
            "--no-dep",
            dest="no_dep",
            action="store_true",
            default=False,
            help="Show only PE binaries without DEP",
        )
        parser.add_argument(
            "--32bit-only",
            dest="only_32bit",
            action="store_true",
            default=False,
            help="Show only 32-bit PE binaries",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"pe fuid={record.get('fuid', '?')} "
            f"{record.get('os', '?')}/{record.get('subsystem', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/pe"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        raw = _ask("No ASLR only (y/n)", "y" if new.get("no_aslr") else "n")
        new["no_aslr"] = raw.lower() in ("y", "yes")
        raw = _ask("No DEP only (y/n)", "y" if new.get("no_dep") else "n")
        new["no_dep"] = raw.lower() in ("y", "yes")
        raw = _ask("32-bit only (y/n)", "y" if new.get("only_32bit") else "n")
        new["only_32bit"] = raw.lower() in ("y", "yes")
