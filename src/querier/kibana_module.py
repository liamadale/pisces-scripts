#!/usr/bin/env python3
"""Kibana/Suricata alert querying: KibanaModule + run_kibana_query().

Used as a backend by kibana_querier.py (thin CLI dispatcher) and available
for future web-layer integration.
"""

import hashlib
import json
import os
from collections import defaultdict

import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

from src.querier.filter_loader import load_filters
from src.querier.zeek_modules.base import ZeekModule, _PRIVATE_CIDRS
from src.utils.cache import cache_path as _cache_path_util, save_cache as _save_cache, load_cache as _load_cache
from src.utils.format import fmt_bytes as _fmt_bytes

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILTERS_DIR = os.path.join(_BASE, "filters")

KIBANA_URL = "https://wa-kibana.cyberrangepoulsbo.com/api/console/proxy"
INDEX = "suricata*"

TIME_RANGES = [
    "now-15m", "now-30m",
    "now-1h",  "now-3h",  "now-6h", "now-12h",
    "now-24h", "now-2d",  "now-3d", "now-7d",
    "now-14d", "now-30d",
]

# Suricata severity → Rich color
SEVERITY_COLORS = {1: "red", 2: "yellow", 3: "cyan"}


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------

def build_query(
    must_not: list[dict],
    time_range: str = "now-24h",
    severity: int = 3,
    cities: list[str] | None = None,
    public_only: bool = False,
    signature: str | None = None,
    min_bytes: int | None = None,
    protocol: str | None = None,
    limit: int = 50,
) -> tuple[dict, dict]:
    """Build the Elasticsearch query and params for Kibana/Suricata.

    Returns:
        (query_body, request_params)
    """
    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
    ]

    # Severity filter: Suricata severity 1=high, so include severity <= requested level
    must_clauses.append({"range": {"alert.severity": {"lte": severity}}})

    if cities and cities != ["all"]:
        must_clauses.append({"terms": {"clientID": cities}})

    if public_only:
        must_not = list(must_not)  # copy to avoid mutating caller's list
        for cidr in _PRIVATE_CIDRS:
            must_not.append({"term": {"src_ip": cidr}})

    if signature:
        must_clauses.append({"match_phrase": {"alert.signature": signature}})

    if min_bytes is not None:
        must_clauses.append({"range": {"flow.bytes_toserver": {"gte": min_bytes}}})

    if protocol:
        must_clauses.append({"term": {"app_proto": protocol.lower()}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": must_clauses,
                "must_not": must_not,
            }
        },
        "_source": [
            "@timestamp",
            "clientID",
            "alert.signature",
            "alert.severity",
            "src_ip",
            "src_port",
            "dest_ip",
            "dest_port",
            "app_proto",
            "flow.bytes_toserver",
            "flow.bytes_toclient",
            "flow_id",
        ],
    }

    params = {
        "path": f"{INDEX}/_search",
        "method": "POST",
    }

    return body, params


# ---------------------------------------------------------------------------
# Kibana HTTP request
# ---------------------------------------------------------------------------

def query_kibana(body: dict, params: dict) -> dict | None:
    username = os.environ.get("PISCES_USERNAME", "")
    password = os.environ.get("PISCES_PASSWORD", "")

    if not username or not password:
        console.print("[red]PISCES_USERNAME and PISCES_PASSWORD must be set in .env[/red]")
        return None

    headers = {
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }

    try:
        resp = requests.post(
            KIBANA_URL,
            params=params,
            json=body,
            headers=headers,
            auth=(username, password),
            verify=False,
            timeout=30,
        )
    except requests.RequestException as exc:
        console.print(f"[red]Kibana request failed: {exc}[/red]")
        return None

    if resp.status_code == 401:
        console.print("[red]Kibana authentication failed — check PISCES_USERNAME/PASSWORD[/red]")
        return None

    if not resp.ok:
        console.print(f"[red]Kibana error {resp.status_code}: {resp.text[:300]}[/red]")
        return None

    return resp.json()


# ---------------------------------------------------------------------------
# City listing (diagnostic)
# ---------------------------------------------------------------------------

def list_cities(time_range: str = "now-7d") -> None:
    """Query a terms aggregation on clientID and print all known cities."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"exists": {"field": "alert.severity"}},
                ]
            }
        },
        "aggs": {
            "cities": {
                "terms": {
                    "field": "clientID",
                    "size": 500,
                    "order": {"_count": "desc"},
                }
            }
        },
    }
    params = {"path": f"{INDEX}/_search", "method": "POST"}

    console.print(f"[dim]Querying clientID values ({time_range})...[/dim]")
    raw = query_kibana(body, params)
    if raw is None:
        return

    buckets = raw.get("aggregations", {}).get("cities", {}).get("buckets", [])
    if not buckets:
        console.print("[yellow]No cities found in the given time range.[/yellow]")
        return

    table = Table(
        title=f"Cities on ELK stack (past {time_range.replace('now-', '')})",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("clientID", style="cyan")
    table.add_column("Alert count", justify="right")

    for bucket in buckets:
        table.add_row(bucket["key"], str(bucket["doc_count"]))

    console.print(table)
    console.print(
        f"[dim]{len(buckets)} city/clientID value(s) found. "
        f"Pass one or more to --cities as a comma-separated list.[/dim]"
    )


# ---------------------------------------------------------------------------
# Cache helper
# ---------------------------------------------------------------------------

def _cache_path(args_hash: str) -> str:
    return _cache_path_util(f"kibana_{args_hash}.json")


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(alerts: list[dict]) -> list[dict]:
    """Deduplicate by (src_ip, signature), counting frequency and collecting cities."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for alert in alerts:
        key = (alert["src_ip"], alert["signature"])
        grouped[key].append(alert)

    deduped = []
    for (_src_ip, _signature), group in sorted(
        grouped.items(), key=lambda kv: -len(kv[1])
    ):
        rep = sorted(group, key=lambda a: a["timestamp"], reverse=True)[0].copy()
        rep["freq"] = len(group)
        rep["cities"] = sorted({a["city"] for a in group if a.get("city")})
        deduped.append(rep)

    return deduped


# ---------------------------------------------------------------------------
# KibanaModule
# ---------------------------------------------------------------------------

class KibanaModule(ZeekModule):
    """ZeekModule subclass for Kibana/Suricata alert queries."""

    SENSOR_PARAM = None  # Kibana has no sensor concept; skip sensor prompt in re-search

    DETAIL_FIELDS = [
        ("Timestamp",  lambda r: r.get("timestamp", "")[:19].replace("T", " ")),
        ("Signature",  lambda r: r.get("signature", "")),
        ("Severity",   lambda r: str(r.get("severity", ""))),
        ("Src IP",     lambda r: r.get("src_ip", "")),
        ("Src Port",   lambda r: str(r["src_port"]) if r.get("src_port") is not None else "—"),
        ("Dest IP",    lambda r: r.get("dest_ip", "")),
        ("Dest Port",  lambda r: str(r["dest_port"]) if r.get("dest_port") is not None else "—"),
        ("Protocol",   lambda r: r.get("proto", "") or "—"),
        ("→Server",    lambda r: _fmt_bytes(r.get("bytes_toserver"))),
        ("→Client",    lambda r: _fmt_bytes(r.get("bytes_toclient"))),
        ("Cities",     lambda r: ", ".join(r.get("cities") or [r.get("city", "")])),
        ("Freq",       lambda r: str(r.get("freq", 1))),
        ("Flow ID",    lambda r: str(r["flow_id"]) if r.get("flow_id") is not None else "—"),
    ]

    def parse_hit(self, src: dict) -> dict:
        """Convert a single _source dict to a normalised alert record."""
        return {
            "timestamp":      src.get("@timestamp", ""),
            "city":           src.get("clientID", ""),
            "signature":      src.get("alert", {}).get("signature", ""),
            "severity":       src.get("alert", {}).get("severity", 3),
            "src_ip":         src.get("src_ip", ""),
            "src_port":       src.get("src_port"),
            "dest_ip":        src.get("dest_ip", ""),
            "dest_port":      src.get("dest_port"),
            "proto":          src.get("app_proto", ""),
            "bytes_toserver": src.get("flow", {}).get("bytes_toserver"),
            "bytes_toclient": src.get("flow", {}).get("bytes_toclient"),
            "flow_id":        src.get("flow_id"),
            "_raw":           src,
        }

    def dedup_key(self, record: dict) -> tuple:
        return (record["src_ip"], record["signature"])

    def describe_record(self, record: dict) -> str:
        sig = record.get("signature", "?")
        src_ip = record.get("src_ip", "?")
        return f"{sig} | {src_ip}"

    def fp_action(self, record: dict) -> None:
        from src.querier.fp_manager import create_filter_interactive
        fp_alert = {
            "src_ip":    record["src_ip"],
            "dest_ip":   record["dest_ip"],
            "dest_port": record["dest_port"],
            "alert": {
                "signature": record["signature"],
                "severity":  record["severity"],
            },
            "clientID": record["cities"][0] if record.get("cities") else record.get("city", ""),
        }
        create_filter_interactive(alert=fp_alert)

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        """Prompt for Kibana-specific re-search fields: severity, cities, signature."""
        sev_raw = _ask("Severity 1-3", new.get("severity", 3))
        try:
            new["severity"] = max(1, min(3, int(sev_raw)))
        except ValueError:
            pass

        new["cities"] = _ask("Cities (comma-sep or 'all')", new.get("cities", "all"))

        sig_raw = _ask("Signature filter (blank to clear)", new.get("signature") or "")
        new["signature"] = sig_raw or None

    def display(self, records: list) -> None:
        """Render alert records as a Rich table."""
        total = sum(a.get("freq", 1) for a in records)
        console.print(
            f"\n[bold]Found {len(records)} unique alert(s) across {total} raw event(s)[/bold] "
            f"(sorted by frequency)\n"
        )

        sig_budget = self._sig_col_budget(records)
        max_sig_len = max((len(a["signature"]) for a in records), default=0)
        footnote_mode = max_sig_len > sig_budget * 2

        table = Table(box=box.SIMPLE_HEAVY, show_lines=True, expand=False)
        table.add_column("#", style="dim", width=3, no_wrap=True)
        table.add_column("Timestamp", style="dim", no_wrap=True)
        table.add_column("City", style="cyan", no_wrap=True)
        if not footnote_mode:
            table.add_column("Signature", ratio=2, overflow="fold")
        table.add_column("Sev", width=3, no_wrap=True)
        table.add_column("Freq", justify="right", width=4, no_wrap=True)
        table.add_column("Src IP", style="yellow", no_wrap=True)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("→Srv", justify="right", no_wrap=True)
        table.add_column("Dst IP", style="dim", no_wrap=True)
        table.add_column("Port", justify="right", no_wrap=True)
        table.add_column("Proto", no_wrap=True)
        table.add_column("→Cli", justify="right", no_wrap=True)
        table.add_column("Flow ID", style="dim", no_wrap=True)

        for idx, alert in enumerate(records, 1):
            sev = alert["severity"]
            sev_color = SEVERITY_COLORS.get(sev, "white")
            sev_text = Text(str(sev), style=f"bold {sev_color}")
            cities_str = ", ".join(alert.get("cities") or [alert.get("city", "")])

            row = [
                str(idx),
                alert["timestamp"][:16].replace("T", " "),
                cities_str,
            ]
            if not footnote_mode:
                row.append(alert["signature"])
            row += [
                sev_text,
                str(alert.get("freq", 1)),
                alert["src_ip"],
                str(alert["src_port"]) if alert.get("src_port") is not None else "—",
                _fmt_bytes(alert.get("bytes_toserver")),
                alert["dest_ip"],
                str(alert["dest_port"]) if alert.get("dest_port") is not None else "—",
                alert.get("proto") or "—",
                _fmt_bytes(alert.get("bytes_toclient")),
                str(alert["flow_id"]) if alert.get("flow_id") is not None else "—",
            ]
            table.add_row(*row)

        console.print(table)

        if footnote_mode:
            console.print("[dim]Signatures:[/dim]")
            for idx, alert in enumerate(records, 1):
                console.print(f"  [dim]{idx:>3}[/dim]  {alert['signature']}")

    @staticmethod
    def _sig_col_budget(alerts: list[dict]) -> int:
        """Estimate characters available to the Signature column at current terminal width."""
        def _maxlen(vals) -> int:
            return max((len(str(v)) for v in vals if v is not None), default=0)

        col_content_widths = [
            3,   # #
            16,  # Timestamp (YYYY-MM-DD HH:MM)
            _maxlen(", ".join(a.get("cities") or [a.get("city", "")]) for a in alerts),
            3,   # Sev
            _maxlen(a.get("freq", 1) for a in alerts),
            _maxlen(a.get("src_ip", "") for a in alerts),
            _maxlen(a.get("src_port") for a in alerts),
            7,   # →Srv
            _maxlen(a.get("dest_ip", "") for a in alerts),
            _maxlen(a.get("dest_port") for a in alerts),
            5,   # Proto
            7,   # →Cli
            _maxlen(a.get("flow_id") for a in alerts),
        ]
        n_cols = len(col_content_widths) + 1  # +1 for Signature itself
        overhead = 2 * n_cols + n_cols + 1
        return max(console.size.width - sum(col_content_widths) - overhead, 5)


# ---------------------------------------------------------------------------
# run_kibana_query
# ---------------------------------------------------------------------------

def run_kibana_query(module: KibanaModule, search_params: dict) -> list:
    """Build + execute a Kibana query; return deduplicated alerts (empty list on error)."""
    if search_params.get("no_filters"):
        must_not: list = []
        console.print("[yellow]--no-filters: all false positive filters disabled[/yellow]")
    else:
        filter_result = load_filters(FILTERS_DIR)
        must_not = filter_result["must_not"]
        fcount = filter_result["filter_count"]
        console.print("[dim]Loading false positive filters...[/dim]")
        console.print(f"[dim]Loaded {fcount} filter file(s) → {len(must_not)} must_not clause(s)[/dim]")
        if filter_result["errors"]:
            for err in filter_result["errors"]:
                console.print(f"[yellow]Filter warning: {err}[/yellow]")

    cities: list[str] | None = None
    cities_val = search_params.get("cities", "all")
    if cities_val and str(cities_val).lower() != "all":
        cities = [c.strip() for c in str(cities_val).split(",")]

    body, params = build_query(
        must_not=must_not,
        time_range=search_params.get("time_range", "now-24h"),
        severity=search_params.get("severity", 3),
        cities=cities,
        public_only=search_params.get("public_only", False),
        signature=search_params.get("signature"),
        min_bytes=search_params.get("min_bytes"),
        protocol=search_params.get("protocol"),
        limit=search_params.get("limit", 50),
    )

    use_cache = search_params.get("use_cache", False)
    raw = None
    cache_key = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]
    cpath = _cache_path(cache_key)

    if use_cache:
        raw = _load_cache(cpath)
        if raw:
            console.print(f"[dim]Using cached response: {cpath}[/dim]")

    if raw is None:
        console.print(f"[dim]Querying Kibana ({search_params.get('time_range', 'now-24h')})...[/dim]")
        raw = query_kibana(body, params)
        if raw is None:
            return []
        _save_cache(raw, cpath)

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        console.print("[yellow]No alerts returned.[/yellow]")
        return []

    alerts = [module.parse_hit(hit.get("_source", {})) for hit in hits]
    alerts = [a for a in alerts if a]
    return _deduplicate(alerts)
