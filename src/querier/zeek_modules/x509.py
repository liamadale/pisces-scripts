#!/usr/bin/env python3
"""Zeek x509 log module — TLS certificate records with community_id IP pivot."""

import threading
from datetime import datetime, timezone

from rich import box
from rich.table import Table

from .base import INDEX, ZeekModule, _sensor_str, console, is_private, query_opensearch

_tl = threading.local()

_CHUNK_SIZE = 1_000


def _cn(dn: str) -> str:
    """Extract CN= component from a distinguished name, or return the full string."""
    for part in dn.split(","):
        if part.strip().upper().startswith("CN="):
            return part.strip()[3:]
    return dn


class X509Module(ZeekModule):
    DATASETS = ["x509"]
    SOURCE_FIELDS = [
        "@timestamp",
        "host.name",
        "destination.port",
        "zeek.x509.id",
        "zeek.x509.certificate.version",
        "zeek.x509.certificate.serial",
        "zeek.x509.certificate.subject",
        "zeek.x509.certificate.issuer",
        "zeek.x509.certificate.not_valid_before",
        "zeek.x509.certificate.not_valid_after",
        "zeek.x509.certificate.key_alg",
        "zeek.x509.certificate.sig_alg",
        "zeek.x509.certificate.key_length",
        "zeek.x509.basic_constraints.ca",
        "zeek.x509.san.dns",
        "zeek.x509.san.ip",
        "network.community_id",
        "event.dataset",
    ]

    # source.ip is intentionally excluded — all IP resolution goes through community_id pivot.
    # run_query() guards src_ip_filter for modules without source.ip in SOURCE_FIELDS.
    SUPPORTS_IP_FILTER = True  # post-filters handle it after pivot resolution

    WEB_CATEGORY = "web"
    WEB_ICON = "fa-certificate"
    EXTRA_PARAMS = ["subject", "issuer", "san", "self_signed", "expired"]
    WEB_COLUMNS = [
        ("Subject", lambda r: _cn(r.get("subject", "") or "")[:22] or "—"),
        ("Issuer", lambda r: _cn(r.get("issuer", "") or "")[:22] or "—"),
        ("Valid Until", lambda r: (r.get("not_after", "") or "")[:10] or "—"),
    ]

    DETAIL_FIELDS = [
        ("Timestamp", lambda r: r.get("timestamp", "—")),
        ("Sensor", lambda r: r.get("sensor", "—")),
        ("Src IP", lambda r: r.get("src_ip", "—")),
        ("Dst IP", lambda r: r.get("dest_ip", "—")),
        ("Dst Port", lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Subject", lambda r: r.get("subject", "—")),
        ("Issuer", lambda r: r.get("issuer", "—")),
        ("Serial", lambda r: r.get("serial", "—")),
        ("Valid From", lambda r: r.get("not_before", "—")),
        ("Valid Until", lambda r: r.get("not_after", "—")),
        (
            "Is CA",
            lambda r: "✓" if r.get("is_ca") else ("✗" if r.get("is_ca") is False else "—"),
        ),
        ("SAN DNS", lambda r: r.get("san_dns", "—") or "—"),
        ("SAN IP", lambda r: r.get("san_ip", "—") or "—"),
        ("Key Alg", lambda r: r.get("key_alg", "—")),
        ("Sig Alg", lambda r: r.get("sig_alg", "—")),
        ("Key Length", lambda r: str(r.get("key_length")) if r.get("key_length") else "—"),
        ("Comm ID", lambda r: r.get("community_id", "—") or "—"),
        ("Freq", lambda r: str(r.get("freq", "—"))),
    ]

    def prepare_hits(self, hits: list) -> None:
        """Batch-lookup community_ids in conn/ssl logs to resolve src/dest IPs."""
        cids = list(
            {
                hit["_source"].get("network", {}).get("community_id")
                for hit in hits
                if hit["_source"].get("network", {}).get("community_id")
            }
        )
        cache: dict = {}

        for i in range(0, len(cids), _CHUNK_SIZE):
            chunk = cids[i : i + _CHUNK_SIZE]
            body = {
                "size": len(chunk) * 2,
                "query": {
                    "bool": {
                        "must": [
                            {"terms": {"event.dataset": ["conn", "ssl"]}},
                            {"terms": {"network.community_id": chunk}},
                        ]
                    }
                },
                "_source": ["network.community_id", "source.ip", "destination.ip"],
            }
            params = {"path": f"{INDEX}/_search", "method": "POST"}
            raw = query_opensearch(body, params)
            if raw is None:
                continue
            for h in raw.get("hits", {}).get("hits", []):
                s = h.get("_source", {})
                cid = s.get("network", {}).get("community_id")
                src_ip = s.get("source", {}).get("ip", "—")
                dest_ip = s.get("destination", {}).get("ip", "—")
                if cid and cid not in cache:
                    cache[cid] = (src_ip, dest_ip)

        _tl.community_id_cache = cache

    def parse_hit(self, src: dict) -> dict:
        zx = src.get("zeek", {}).get("x509", {})
        cert = zx.get("certificate", {})
        san = zx.get("san", {})
        bc = zx.get("basic_constraints", {})
        community_id = src.get("network", {}).get("community_id", "")

        cache = getattr(_tl, "community_id_cache", {})
        src_ip, dest_ip = cache.get(community_id, ("—", "—"))

        san_dns_raw = san.get("dns")
        if isinstance(san_dns_raw, list):
            san_dns = ", ".join(san_dns_raw)
        else:
            san_dns = san_dns_raw or ""

        san_ip_raw = san.get("ip")
        if isinstance(san_ip_raw, list):
            san_ip = ", ".join(san_ip_raw)
        else:
            san_ip = san_ip_raw or ""

        return {
            "timestamp": src.get("@timestamp", ""),
            "sensor": src.get("host", {}).get("name", ""),
            "log_type": src.get("event", {}).get("dataset", ""),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "dest_port": src.get("destination", {}).get("port"),
            "subject": cert.get("subject", ""),
            "issuer": cert.get("issuer", ""),
            "not_before": cert.get("not_valid_before", ""),
            "not_after": cert.get("not_valid_after", ""),
            "is_ca": bc.get("ca"),
            "san_dns": san_dns,
            "san_ip": san_ip,
            "key_alg": cert.get("key_alg", ""),
            "sig_alg": cert.get("sig_alg", ""),
            "key_length": cert.get("key_length"),
            "serial": cert.get("serial", ""),
            "community_id": community_id,
            "_raw": src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (
            record.get("dest_ip", ""),
            record.get("subject", ""),
            record.get("issuer", ""),
        )

    def build_extra_must(self, search_params: dict) -> tuple:
        clauses: list = []
        post_filters: list = []

        if search_params.get("subject"):
            clauses.append(
                {"match_phrase": {"zeek.x509.certificate.subject": search_params["subject"]}}
            )
        if search_params.get("issuer"):
            clauses.append(
                {"match_phrase": {"zeek.x509.certificate.issuer": search_params["issuer"]}}
            )
        if search_params.get("san"):
            clauses.append({"match_phrase": {"zeek.x509.san.dns": search_params["san"]}})

        if search_params.get("self_signed"):
            post_filters.append(
                lambda r: (
                    _cn(r.get("subject", "")) == _cn(r.get("issuer", "")) and bool(r.get("subject"))
                )
            )

        if search_params.get("expired"):
            now = datetime.now(timezone.utc)

            def _is_expired(r: dict, _now: datetime = now) -> bool:
                na = r.get("not_after", "")
                if not na:
                    return False
                try:
                    return datetime.fromisoformat(na.replace("Z", "+00:00")) < _now
                except ValueError:
                    return False

            post_filters.append(_is_expired)

        if search_params.get("src_ip"):
            ip = search_params["src_ip"]
            post_filters.append(lambda r, _ip=ip: r.get("src_ip") == _ip)
        if search_params.get("dest_ip"):
            ip = search_params["dest_ip"]
            post_filters.append(lambda r, _ip=ip: r.get("dest_ip") == _ip)
        if search_params.get("public_only"):
            post_filters.append(lambda r: not is_private(r.get("src_ip", "")))

        return clauses, post_filters

    def display(self, records: list) -> None:
        now = datetime.now(timezone.utc)
        total = sum(r["freq"] for r in records)
        console.print(
            f"\n[bold]Found {len(records)} unique certificate(s)"
            f" across {total} raw record(s)[/bold] (sorted by frequency)\n"
        )

        table = Table(box=box.SIMPLE_HEAVY, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("HH:MM", style="dim", no_wrap=True)
        table.add_column("Sensor", style="cyan", no_wrap=True)
        table.add_column("Dst IP:Port", style="yellow", no_wrap=True)
        table.add_column("Subject CN", no_wrap=True, max_width=28, overflow="ellipsis")
        table.add_column("Issuer CN", no_wrap=True, max_width=22, overflow="ellipsis")
        table.add_column("Valid Until", no_wrap=True)
        table.add_column("SANs", no_wrap=True, max_width=20, overflow="ellipsis")
        table.add_column("Freq", justify="right", no_wrap=True)

        for idx, rec in enumerate(records, 1):
            dest_ip = rec.get("dest_ip", "—") or "—"
            dest_port = rec.get("dest_port")
            dst_str = f"{dest_ip}:{dest_port}" if dest_port else dest_ip

            subject_cn = _cn(rec.get("subject", "") or "")
            issuer_raw = rec.get("issuer", "") or ""
            issuer_cn = _cn(issuer_raw)

            # Self-signed flag
            if subject_cn and subject_cn == issuer_cn:
                issuer_display = f"[self] {issuer_cn}"
            else:
                issuer_display = issuer_cn or "—"

            # Validity colouring
            not_after = rec.get("not_after", "") or ""
            valid_until = not_after[:10] if not_after else "—"
            try:
                exp_dt = (
                    datetime.fromisoformat(not_after.replace("Z", "+00:00")) if not_after else None
                )
            except ValueError:
                exp_dt = None

            if exp_dt and exp_dt < now:
                valid_until = f"[red]{valid_until}[/red]"
            elif exp_dt and (exp_dt - now).days < 30:
                valid_until = f"[yellow]{valid_until}[/yellow]"

            san_dns = rec.get("san_dns", "") or "—"

            table.add_row(
                str(idx),
                rec["timestamp"][5:16].replace("T", " "),
                _sensor_str(rec),
                dst_str,
                subject_cn or "—",
                issuer_display,
                valid_until,
                san_dns,
                str(rec["freq"]),
            )

        console.print(table)

    def add_args(self, parser) -> None:
        parser.add_argument("--subject", dest="subject", help="Filter by certificate subject")
        parser.add_argument("--issuer", dest="issuer", help="Filter by certificate issuer")
        parser.add_argument("--san", dest="san", help="Filter by SAN DNS entry")
        parser.add_argument(
            "--self-signed",
            dest="self_signed",
            action="store_true",
            help="Show only self-signed certificates (subject == issuer)",
        )
        parser.add_argument(
            "--expired",
            dest="expired",
            action="store_true",
            help="Show only expired certificates",
        )

    def describe_record(self, record: dict) -> str:
        subject = _cn(record.get("subject", "") or "") or record.get("dest_ip", "?")
        return f"x509 {record.get('dest_ip', '?')} [{subject}]"

    def fp_signature(self, record: dict) -> str:
        return "zeek/x509"

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        val = _ask("Subject filter", new.get("subject"))
        new["subject"] = val if val else None
        val = _ask("Issuer filter", new.get("issuer"))
        new["issuer"] = val if val else None
        val = _ask("SAN DNS filter", new.get("san"))
        new["san"] = val if val else None
        raw = _ask("Self-signed only (y/n)", "y" if new.get("self_signed") else "n")
        new["self_signed"] = raw.lower() in ("y", "yes")
        raw = _ask("Expired only (y/n)", "y" if new.get("expired") else "n")
        new["expired"] = raw.lower() in ("y", "yes")
