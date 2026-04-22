#!/usr/bin/env python3
"""Zeek ftp log module — FTP session records (cleartext credentials and file transfers)."""

from rich import box
from rich.table import Table

from .base import ZeekModule, _fmt_bytes, _sensor_str, console


class FtpModule(ZeekModule):
    DATASETS = ["ftp"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "source.ip",
        "source.port",
        "destination.ip",
        "destination.port",
        "zeek.ftp.user",
        "zeek.ftp.password",
        "zeek.ftp.command",
        "zeek.ftp.arg",
        "zeek.ftp.mime_type",
        "zeek.ftp.file_size",
        "zeek.ftp.reply_code",
        "zeek.ftp.reply_msg",
        "zeek.ftp.data_channel.passive",
        "zeek.ftp.data_channel.orig_h",
        "zeek.ftp.data_channel.resp_h",
        "zeek.ftp.data_channel.resp_p",
        "zeek.ftp.fuid",
        "network.community_id",
        "network.direction",
        "event.dataset",
    ]

    WEB_CATEGORY = "files"
    WEB_ICON = "fa-file-arrow-up"
    EXTRA_PARAMS = ["user", "command", "reply_code", "anon_only"]
    WEB_COLUMNS = [
        ("User", lambda r: r.get("user", "—") or "—"),
        ("Command", lambda r: r.get("command", "—") or "—"),
        ("Reply", lambda r: str(r.get("reply_code")) if r.get("reply_code") else "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Src Port", lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("User", lambda r: r.get("user", "—")),
        ("Password", lambda r: r.get("password", "—") or "—"),
        ("Command", lambda r: r.get("command", "—")),
        ("Arg", lambda r: r.get("arg", "—") or "—"),
        ("MIME Type", lambda r: r.get("mime_type", "—") or "—"),
        ("File Size", lambda r: _fmt_bytes(r.get("file_size"))),
        ("Reply Code", lambda r: str(r.get("reply_code")) if r.get("reply_code") else "—"),
        ("Reply Msg", lambda r: r.get("reply_msg", "—") or "—"),
        (
            "Passive",
            lambda r: "✓" if r.get("passive") else ("✗" if r.get("passive") is False else "—"),
        ),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Direction", lambda r: r.get("direction", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def parse_hit(self, src: dict) -> dict:
        zf = src.get("zeek", {}).get("ftp", {})
        dc = zf.get("data_channel", {})
        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src.get("source", {}).get("ip", ""),
            "src_port": src.get("source", {}).get("port"),
            "dest_ip": src.get("destination", {}).get("ip", ""),
            "dest_port": src.get("destination", {}).get("port"),
            "user": zf.get("user", ""),
            "password": zf.get("password", ""),
            "command": zf.get("command", ""),
            "arg": zf.get("arg", ""),
            "mime_type": zf.get("mime_type", ""),
            "file_size": zf.get("file_size"),
            "reply_code": zf.get("reply_code"),
            "reply_msg": zf.get("reply_msg", ""),
            "passive": dc.get("passive"),
            "community_id": src.get("network", {}).get("community_id", ""),
            "direction": src.get("network", {}).get("direction", ""),
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("src_ip", ""),
            record.get("dest_ip", ""),
            record.get("user", ""),
            record.get("command", ""),
            record.get("arg", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("user"):
            clauses.append({"match_phrase": {"zeek.ftp.user": search_params["user"]}})
        if search_params.get("command"):
            clauses.append({"term": {"zeek.ftp.command": search_params["command"]}})
        if search_params.get("reply_code"):
            clauses.append({"term": {"zeek.ftp.reply_code": search_params["reply_code"]}})
        if search_params.get("anon_only"):
            _anon = {"anonymous", "ftp", "guest"}
            post_filters.append(lambda r, _a=_anon: r.get("user", "").lower() in _a)

        return clauses, post_filters

    def display(self, records: list) -> None:
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique FTP session record(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Src IP → Dst IP", style="yellow", no_wrap=True, max_width=36)
        table.add_column("User", no_wrap=True, max_width=16, overflow="ellipsis")
        table.add_column("Command", no_wrap=True)
        table.add_column("Arg", no_wrap=True, max_width=22, overflow="ellipsis")
        table.add_column("Reply", justify="right", no_wrap=True)
        table.add_column("Size", justify="right", no_wrap=True)
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            src_ip = rec.get("src_ip", "") or "—"
            dest_ip = rec.get("dest_ip", "") or "—"
            flow = f"{src_ip} → {dest_ip}"

            user = rec.get("user", "") or "—"
            is_anon = user.lower() in ("anonymous", "ftp", "guest")
            user_col = f"[yellow]{user}[/yellow]" if is_anon else user

            cmd = rec.get("command", "") or "—"
            cmd_col = f"[orange1]{cmd}[/orange1]" if cmd == "STOR" else cmd

            reply_code = rec.get("reply_code")
            reply_str = str(reply_code) if reply_code else "—"
            if reply_code and int(reply_code) >= 400:
                reply_col = f"[red]{reply_str}[/red]"
            else:
                reply_col = reply_str

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                flow,
                user_col,
                cmd_col,
                rec.get("arg", "") or "—",
                reply_col,
                _fmt_bytes(rec.get("file_size")),
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--user", dest="user", help="Filter by FTP username (match_phrase)")
        parser.add_argument(
            "--command",
            dest="command",
            help="Filter by FTP command (RETR, STOR, DELE, LIST, etc.)",
        )
        parser.add_argument(
            "--reply-code", dest="reply_code", help="Filter by reply code (exact match)"
        )
        parser.add_argument(
            "--anon-only",
            dest="anon_only",
            action="store_true",
            help="Show only anonymous sessions (user = anonymous/ftp/guest)",
        )

    def describe_record(self, record: dict) -> str:
        user = record.get("user") or "?"
        cmd = record.get("command") or ""
        arg = record.get("arg") or ""
        detail = f"{cmd} {arg}".strip() or "?"
        return f"ftp {record.get('src_ip', '?')} → {record.get('dest_ip', '?')} [{user}: {detail}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/ftp"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("User filter", new.get("user"))
        new["user"] = val if val else None
        val = _ask("Command filter (RETR/STOR/LIST/DELE)", new.get("command"))
        new["command"] = val if val else None
        val = _ask("Reply code filter", new.get("reply_code"))
        new["reply_code"] = val if val else None
        raw = _ask("Anonymous only (y/n)", "y" if new.get("anon_only") else "n")
        new["anon_only"] = raw.lower() in ("y", "yes")
