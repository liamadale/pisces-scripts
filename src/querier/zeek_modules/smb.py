#!/usr/bin/env python3
"""Zeek smb module — combined smb_files + smb_mapping records."""

from rich.table import Table
from rich import box

from .base import ZeekModule, _sensor_str, console


class SmbModule(ZeekModule):
    DATASETS = ["smb_files", "smb_mapping"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.smb_files.action",
        "zeek.smb_files.name",
        "zeek.smb_files.path",
        "zeek.smb_mapping.path",
        "zeek.smb_mapping.service",
        "network.community_id",
        "network.direction",
        "event.dataset",
    ]

    def build_extra_must(self, search_params: dict) -> list:
        clauses = []
        if search_params.get("smb_share"):
            # Match on either smb_mapping.path or smb_files.path
            clauses.append({
                "bool": {
                    "should": [
                        {"match_phrase": {"zeek.smb_mapping.path": search_params["smb_share"]}},
                        {"match_phrase": {"zeek.smb_files.path": search_params["smb_share"]}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if search_params.get("smb_action"):
            clauses.append({"term": {"zeek.smb_files.action": search_params["smb_action"]}})
        return clauses

    def parse_hit(self, src: dict) -> dict:
        dataset = src.get("event", {}).get("dataset", "")
        smb_files = src.get("zeek", {}).get("smb_files", {})
        smb_mapping = src.get("zeek", {}).get("smb_mapping", {})

        if dataset == "smb_mapping":
            smb_type = "mapping"
            smb_action = smb_mapping.get("service", "")
            smb_path = smb_mapping.get("path", "")
            smb_name = ""
            smb_service = smb_mapping.get("service", "")
        else:
            smb_type = "files"
            smb_action = smb_files.get("action", "")
            smb_path = smb_files.get("path", "")
            smb_name = smb_files.get("name", "")
            smb_service = ""

        return {
            "timestamp":   src.get("@timestamp", ""),
            "sensor":      src.get("host", {}).get("name", ""),
            "log_type":    dataset,
            "src_ip":      src.get("source", {}).get("ip", ""),
            "src_port":    src.get("source", {}).get("port"),
            "dest_ip":     src.get("destination", {}).get("ip", ""),
            "dest_port":   src.get("destination", {}).get("port"),
            "smb_type":    smb_type,
            "smb_action":  smb_action,
            "smb_path":    smb_path,
            "smb_name":    smb_name,
            "smb_service":  smb_service,
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction":    src.get("network", {}).get("direction", ""),
            "_raw":         src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("smb_path", ""),
        )

    DETAIL_FIELDS = [
        ("Timestamp",      lambda r: r.get("timestamp", "—")),
        ("Sensor",         lambda r: r.get("sensor", "—")),
        ("Src IP",         lambda r: r.get("src_ip", "—")),
        ("Dst IP",         lambda r: r.get("dest_ip", "—") or "—"),
        ("Type",           lambda r: r.get("smb_type", "—") or "—"),
        ("Action/Service", lambda r: r.get("smb_action", "—") or "—"),
        ("Path",           lambda r: r.get("smb_path", "—") or "—"),
        ("Name",           lambda r: r.get("smb_name", "—") or "—"),
        ("Comm ID",        lambda r: r.get("community_id", "—") or "—"),
        ("Direction",      lambda r: r.get("direction", "—") or "—"),
        ("Freq",           lambda r: str(r.get("freq", "—"))),
    ]

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique SMB flow(s) across {total} raw record(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Flow", style="yellow", no_wrap=True, max_width=32, overflow="ellipsis")
        table.add_column("Path", no_wrap=True, max_width=30, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "")
            dest_ip = rec.get("dest_ip", "")
            flow = f"{src_ip} → {dest_ip}"
            table.add_row(
                str(idx),
                rec["timestamp"][11:16],
                _sensor_str(rec),
                flow,
                rec.get("smb_path", "") or "—",
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument(
            "--share", dest="smb_share",
            help="Filter by SMB share path (match_phrase on smb_mapping.path OR smb_files.path)",
        )
        parser.add_argument(
            "--action", dest="smb_action",
            help="Filter by SMB file action (term on zeek.smb_files.action)",
        )

    def describe_record(self, record: dict) -> str:
        return (
            f"smb {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} "
            f"{record.get('smb_path', '?')}"
        )

    def fp_signature(self, record: dict) -> str:
        return "zeek/smb"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("SMB share path filter", new.get("smb_share"))
        new["smb_share"] = val if val else None
        val = _ask("SMB action filter", new.get("smb_action"))
        new["smb_action"] = val if val else None
