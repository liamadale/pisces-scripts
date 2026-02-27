#!/usr/bin/env python3
"""Shared infrastructure for PISCES OpenSearch / Malcolm / Zeek querier modules.

All constants, utility functions, OpenSearch interaction, query building,
deduplication, and interactive loop logic live here.  Protocol modules
(conn, dns, http, …) import from this file and the ZeekModule base class.
"""

import hashlib
import ipaddress
import json
import os
import readline  # noqa: F401 — enables arrow-key history in input()
from collections import defaultdict

import requests
import urllib3
from rich.console import Console
from rich.table import Table
from rich import box

from src.utils.format import fmt_bytes, fmt_dur
from src.utils.cache import cache_path as _cache_path_util, save_cache, load_cache
from src.utils.terminal import confirm_exit, prompt

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

# Backwards-compatible aliases — zeek modules import these names from .base
_fmt_bytes = fmt_bytes
_fmt_dur = fmt_dur

# Project root — four dirname() calls up from src/querier/zeek_modules/base.py
_BASE = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
    )
)
FILTERS_DIR = os.path.join(_BASE, "filters")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://pisces-opensearch.cyberrangepoulsbo.com")
INDEX = "arkime_sessions3-*"

# Field name translation: existing YAML filter field → Malcolm/Zeek field
FIELD_MAP = {
    "src_ip":    "source.ip",
    "dest_ip":   "destination.ip",
    "src_port":  "source.port",
    "dest_port": "destination.port",
    "app_proto": "network.protocol",
    "clientID":  "host.name",
}

TIME_RANGES = [
    "now-15m", "now-30m",
    "now-1h",  "now-3h",  "now-6h", "now-12h",
    "now-24h", "now-2d",  "now-3d", "now-7d",
    "now-14d", "now-30d",
]

# Non-routable CIDRs excluded by --public-only.
_PRIVATE_CIDRS = [
    # IPv4
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",   # link-local / APIPA
    # IPv6
    "::1/128",          # loopback
    "fe80::/10",        # link-local
    "fc00::/7",         # unique-local (fd00::/8 etc.)
    "ff00::/8",         # multicast
]


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _first(val):
    """Return val as-is if scalar, or the first element if it's a list."""
    if isinstance(val, list):
        return val[0] if val else None
    return val


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in _PRIVATE_CIDRS)
    except ValueError:
        return False



def _sensor_str(rec: dict) -> str:
    """Format the sensor(s) column for display."""
    sensors = rec.get("sensors")
    vals = sensors if sensors else ([rec["sensor"]] if rec.get("sensor") else [])
    return ", ".join(v.removeprefix("hedgehog-") for v in vals)


# ---------------------------------------------------------------------------
# Field remapping
# ---------------------------------------------------------------------------

def _remap_clause(clause: dict) -> dict:
    """Recursively remap Kibana field names to Malcolm/Zeek field names.

    Walks a DSL clause dict and renames any key found in FIELD_MAP.
    Handles term, terms, range, match_phrase, bool (recurses into
    must/must_not/should/filter). Pure function — returns a new dict.
    """
    if not isinstance(clause, dict):
        return clause

    result = {}
    for key, value in clause.items():
        if key in ("term", "terms", "range", "match_phrase", "match", "wildcard", "prefix", "regexp"):
            remapped_inner = {}
            for field, field_val in value.items():
                new_field = FIELD_MAP.get(field, field)
                remapped_inner[new_field] = field_val
            result[key] = remapped_inner
        elif key == "bool":
            new_bool = {}
            for bool_key, bool_val in value.items():
                if bool_key in ("must", "must_not", "should", "filter"):
                    if isinstance(bool_val, list):
                        new_bool[bool_key] = [_remap_clause(c) for c in bool_val]
                    else:
                        new_bool[bool_key] = _remap_clause(bool_val)
                else:
                    new_bool[bool_key] = bool_val
            result[key] = new_bool
        else:
            result[key] = value

    return result


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_path(args_hash: str) -> str:
    return _cache_path_util(f"opensearch_{args_hash}.json")


_save_cache = save_cache
_load_cache = load_cache


# ---------------------------------------------------------------------------
# OpenSearch session + query
# ---------------------------------------------------------------------------

def _opensearch_session() -> tuple:
    """Return (base_url, authenticated Session) or (None, None) on missing creds."""
    opensearch_url = os.environ.get("OPENSEARCH_URL", OPENSEARCH_URL)
    username = os.environ.get("PISCES_USERNAME", "")
    password = os.environ.get("PISCES_PASSWORD", "")

    if not username or not password:
        console.print("[red]PISCES_USERNAME and PISCES_PASSWORD must be set in .env[/red]")
        return None, None

    session = requests.Session()
    session.auth = (username, password)
    session.verify = False
    session.headers.update({
        "Content-Type": "application/json",
        "osd-xsrf": "true",
    })
    return opensearch_url, session


def query_opensearch(body: dict, params: dict) -> dict | None:
    base_url, session = _opensearch_session()
    if session is None:
        return None

    try:
        resp = session.post(
            base_url + "/api/console/proxy",
            params=params,
            json=body,
            timeout=30,
        )
    except requests.RequestException as exc:
        console.print(f"[red]OpenSearch request failed: {exc}[/red]")
        return None

    if resp.status_code == 401:
        console.print("[red]OpenSearch authentication failed — check PISCES_USERNAME/PASSWORD[/red]")
        return None

    if not resp.ok:
        console.print(f"[red]OpenSearch error {resp.status_code}: {resp.text[:300]}[/red]")
        return None

    return resp.json()


# ---------------------------------------------------------------------------
# Filter loading
# ---------------------------------------------------------------------------

def load_with_remap(filters_dir: str) -> tuple:
    """Load filters and remap field names. Returns (must_not, fcount, errors)."""
    from src.querier.filter_loader import load_filters
    filter_result = load_filters(filters_dir)
    raw_must_not = filter_result["must_not"]
    fcount = filter_result["filter_count"]
    errors = filter_result["errors"]
    must_not = [_remap_clause(c) for c in raw_must_not]
    return must_not, fcount, errors


# ---------------------------------------------------------------------------
# Query building
# ---------------------------------------------------------------------------

def build_base_query(
    must_not: list,
    extra_must: list,
    source_fields: list,
    limit: int,
    time_range: str,
    sensors: list | None,
    datasets: list,
    public_only: bool = False,
    src_ip_filter: str | None = None,
    direction: str | None = None,
    min_risk_score: int | None = None,
) -> tuple:
    """Build the OpenSearch query body and request params.

    datasets: list of event.dataset values, or ["all"] to omit the filter.
    """
    must_clauses: list = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
    ]

    if datasets and datasets != ["all"]:
        must_clauses.append({"terms": {"event.dataset": datasets}})

    if sensors:
        must_clauses.append({"terms": {"host.name": sensors}})

    if src_ip_filter:
        must_clauses.append({"term": {"source.ip": src_ip_filter}})

    if direction:
        must_clauses.append({"term": {"network.direction": direction}})

    if min_risk_score:
        must_clauses.append({"range": {"event.risk_score_norm": {"gte": min_risk_score}}})

    must_clauses.extend(extra_must)

    effective_must_not = list(must_not)
    if public_only:
        for cidr in _PRIVATE_CIDRS:
            effective_must_not.append({"term": {"source.ip": cidr}})

    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "bool": {
                "must": must_clauses,
                "must_not": effective_must_not,
            }
        },
        "_source": source_fields,
    }

    params = {
        "path": f"{INDEX}/_search",
        "method": "POST",
    }

    return body, params


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_zeek(records: list, key_fn) -> list:
    """Deduplicate records by key_fn, keeping the most recent per group.

    Sorts output by descending frequency so highest-volume flows appear first.
    """
    grouped: dict = defaultdict(list)
    for rec in records:
        key = key_fn(rec)
        grouped[key].append(rec)

    deduped = []
    for _key, group in sorted(grouped.items(), key=lambda kv: -len(kv[1])):
        rep = sorted(group, key=lambda r: r["timestamp"], reverse=True)[0].copy()
        rep["freq"] = len(group)
        rep["sensors"] = sorted({r["sensor"] for r in group if r.get("sensor")})
        deduped.append(rep)

    return deduped


# ---------------------------------------------------------------------------
# run_query
# ---------------------------------------------------------------------------

def run_query(module, search_params: dict) -> list:
    """Execute a full query cycle: load filters, build query, fetch, parse, dedup."""
    if search_params.get("no_filters"):
        must_not: list = []
        console.print("[yellow]--no-filters: all false positive filters disabled[/yellow]")
    else:
        must_not, fcount, errors = load_with_remap(FILTERS_DIR)
        console.print("[dim]Loading false positive filters...[/dim]")
        console.print(f"[dim]Loaded {fcount} filter file(s) → {len(must_not)} must_not clause(s)[/dim]")
        for err in errors:
            console.print(f"[yellow]Filter warning: {err}[/yellow]")

    sensors: list | None = None
    sensor_val = search_params.get("sensor", "all")
    if sensor_val and str(sensor_val).lower() != "all":
        sensors = [s.strip() for s in str(sensor_val).split(",")]

    extra_must = module.build_extra_must(search_params)

    body, params = build_base_query(
        must_not=must_not,
        extra_must=extra_must,
        source_fields=module.SOURCE_FIELDS,
        limit=search_params.get("limit", 500),
        time_range=search_params.get("time_range", "now-24h"),
        sensors=sensors,
        datasets=module.DATASETS,
        public_only=search_params.get("public_only", False),
        src_ip_filter=search_params.get("src_ip"),
        direction=search_params.get("direction"),
        min_risk_score=search_params.get("min_risk_score"),
    )

    # Cache handling
    use_cache = search_params.get("use_cache", False)
    raw = None
    cache_key = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]
    cpath = _cache_path(cache_key)

    if use_cache:
        raw = _load_cache(cpath)
        if raw:
            console.print(f"[dim]Using cached response: {cpath}[/dim]")

    if raw is None:
        console.print(
            f"[dim]Querying OpenSearch / Malcolm ({search_params.get('time_range', 'now-24h')})...[/dim]"
        )
        raw = query_opensearch(body, params)
        if raw is None:
            return []
        _save_cache(raw, cpath)

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        console.print("[yellow]No records returned.[/yellow]")
        return []

    records = [module.parse_hit(hit.get("_source", {})) for hit in hits]
    records = [r for r in records if r]
    return deduplicate_zeek(records, module.dedup_key)


# ---------------------------------------------------------------------------
# Interactive loop
# ---------------------------------------------------------------------------

def interactive_loop(records: list, search_params: dict, module) -> None:
    """Interactive post-display prompt — dispatch to module for protocol actions."""
    from src.enricher.threat_intel import enrich_ip
    from src.mantis.mantis_search import search as mantis_search, display_results as display_mantis
    from src.mantis.mantis_submit import submit_interactive

    last_record: dict | None = None

    while True:
        console.print("")
        if last_record:
            r = last_record["record"]
            hint = module.describe_record(r)
            console.print(f"[dim]↩  Last: #{last_record['idx']} {hint}[/dim]")
        console.print(
            "[bold cyan]Action[/bold cyan] — enter record # / \\[r]e-search / \\[p]rint (CTRL+C to exit):"
        )
        try:
            raw = prompt("  > ").strip().lower()
        except KeyboardInterrupt:
            if confirm_exit():
                break
            continue

        if raw in ("r", "research", "search"):
            search_params = _search_again_prompt(search_params, module)
            new_records = run_query(module, search_params)
            if new_records:
                records = new_records
                module.display(records)
            continue

        if raw in ("p", "print"):
            module.display(records)
            continue

        if not raw:
            continue

        readline.add_history(raw)

        try:
            idx = int(raw) - 1
            if idx < 0:
                raise ValueError
            record = records[idx]
        except (ValueError, IndexError):
            console.print("[red]Invalid selection.[/red]")
            continue

        src_ip = record.get("src_ip", "")
        module.display_detail(record, idx + 1)
        console.print("  \\[e]nrich  \\[f]alse positive  \\[m]antis search  \\[t]icket  \\[s]kip")

        try:
            action = prompt("  Action: ").strip().lower()
        except KeyboardInterrupt:
            console.print("[dim]Cancelled.[/dim]")
            continue

        key = action[:1]
        if key:
            readline.add_history(action)

        if key == "e":
            enrich_ip(src_ip)
        elif key == "f":
            module.fp_action(record)
        elif key == "m":
            dest_ip = record.get("dest_ip", "")

            def _is_public(ip: str) -> bool:
                try:
                    return not ipaddress.ip_address(ip).is_private
                except ValueError:
                    return True

            queries = dict.fromkeys(ip for ip in [src_ip, dest_ip] if ip and _is_public(ip))
            combined: list = []
            seen_ids: set = set()
            for q in queries:
                console.print(f"[dim]Searching Mantis for '{q}'...[/dim]")
                for r in mantis_search(q, live=True):
                    if r["id"] not in seen_ids:
                        combined.append(r)
                        seen_ids.add(r["id"])
            display_mantis(combined)
        elif key == "t":
            submit_record = record.get("_raw", {})
            submit_record.setdefault("src_ip", src_ip)
            submit_record.setdefault("dest_ip", record.get("dest_ip", ""))
            submit_record.setdefault(
                "clientID",
                (record.get("sensors") or [record.get("sensor", "")])[0],
            )
            submit_interactive(submit_record)

        last_record = {"idx": idx + 1, "record": record}


# ---------------------------------------------------------------------------
# Search-again prompt
# ---------------------------------------------------------------------------

def _search_again_prompt(current: dict, module) -> dict:
    """Prompt for new search parameters, shared + module-specific."""
    console.print("\n[bold cyan]New Search Parameters[/bold cyan] [dim](Enter to keep current)[/dim]")
    console.print("[dim]Time ranges: " + "  ".join(TIME_RANGES) + "[/dim]")

    def _ask(label: str, current_val) -> str:
        """Prompt for a value; returns user input or preserves current (empty string for None)."""
        display = "" if current_val is None else str(current_val)
        try:
            val = prompt(f"  {label} [{display}]: ").strip()
            return val if val else display
        except KeyboardInterrupt:
            console.print("")
            return display

    new = dict(current)
    new["time_range"] = _ask("Time range", current.get("time_range", "now-24h"))
    new["sensor"] = _ask("Sensor (comma-sep or 'all')", current.get("sensor", "all"))

    pub_raw = _ask("Public only (y/n)", "y" if current.get("public_only") else "n")
    new["public_only"] = pub_raw.lower() in ("y", "yes")

    src_raw = _ask("Src IP filter (blank to clear)", current.get("src_ip"))
    new["src_ip"] = src_raw if src_raw else None

    dir_raw = _ask("Direction filter (inbound/outbound/internal/external/blank)", current.get("direction"))
    new["direction"] = dir_raw if dir_raw else None

    limit_raw = _ask("Limit", current.get("limit", 500))
    try:
        new["limit"] = int(limit_raw)
    except ValueError:
        new["limit"] = current.get("limit", 500)

    # Module-specific search params
    module.add_search_params_prompt(new, _ask)

    return new


# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------

def list_sensors(time_range: str = "now-7d") -> None:
    """Aggregate on host.name and print all known sensors."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"exists": {"field": "event.dataset"}},
                ]
            }
        },
        "aggs": {
            "sensors": {
                "terms": {
                    "field": "host.name",
                    "size": 500,
                    "order": {"_count": "desc"},
                }
            }
        },
    }
    params = {"path": f"{INDEX}/_search", "method": "POST"}

    console.print(f"[dim]Querying host.name values ({time_range})...[/dim]")
    raw = query_opensearch(body, params)
    if raw is None:
        return

    buckets = raw.get("aggregations", {}).get("sensors", {}).get("buckets", [])
    if not buckets:
        console.print("[yellow]No sensors found in the given time range.[/yellow]")
        return

    table = Table(
        title=f"Malcolm sensors (past {time_range.replace('now-', '')})",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("host.name", style="cyan")
    table.add_column("Record count", justify="right")

    for bucket in buckets:
        table.add_row(bucket["key"], str(bucket["doc_count"]))

    console.print(table)
    console.print(
        f"[dim]{len(buckets)} sensor(s) found. "
        f"Pass one or more to --sensor as a comma-separated list.[/dim]"
    )


def list_log_types(time_range: str = "now-7d") -> None:
    """Aggregate on event.dataset and print all Zeek log types present."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"exists": {"field": "event.dataset"}},
                ]
            }
        },
        "aggs": {
            "log_types": {
                "terms": {
                    "field": "event.dataset",
                    "size": 200,
                    "order": {"_count": "desc"},
                }
            }
        },
    }
    params = {"path": f"{INDEX}/_search", "method": "POST"}

    console.print(f"[dim]Querying event.dataset values ({time_range})...[/dim]")
    raw = query_opensearch(body, params)
    if raw is None:
        return

    buckets = raw.get("aggregations", {}).get("log_types", {}).get("buckets", [])
    if not buckets:
        console.print("[yellow]No log types found in the given time range.[/yellow]")
        return

    table = Table(
        title=f"Zeek log types in Malcolm (past {time_range.replace('now-', '')})",
        box=box.SIMPLE_HEAVY,
    )
    table.add_column("event.dataset (log type)", style="cyan")
    table.add_column("Record count", justify="right")

    for bucket in buckets:
        table.add_row(bucket["key"], str(bucket["doc_count"]))

    console.print(table)
    console.print(
        f"[dim]{len(buckets)} log type(s) found. Pass one to --log-type (or 'all').[/dim]"
    )


def list_indices() -> None:
    """List all indices in the cluster sorted by doc count."""
    base_url, session = _opensearch_session()
    if session is None:
        return

    try:
        resp = session.post(
            base_url + "/api/console/proxy",
            params={
                "path": "_cat/indices?format=json&s=docs.count:desc&h=index,docs.count,store.size,health",
                "method": "GET",
            },
            timeout=30,
        )
    except requests.RequestException as exc:
        console.print(f"[red]OpenSearch request failed: {exc}[/red]")
        return

    if not resp.ok:
        console.print(f"[red]OpenSearch error {resp.status_code}: {resp.text[:300]}[/red]")
        return

    indices = resp.json()
    if not indices:
        console.print("[yellow]No indices found.[/yellow]")
        return

    table = Table(title="OpenSearch indices (sorted by doc count)", box=box.SIMPLE_HEAVY)
    table.add_column("Index", style="cyan")
    table.add_column("Docs", justify="right")
    table.add_column("Size", justify="right")
    table.add_column("Health", justify="center")

    for entry in indices:
        health = entry.get("health", "")
        health_color = {"green": "green", "yellow": "yellow", "red": "red"}.get(health, "white")
        table.add_row(
            entry.get("index", ""),
            entry.get("docs.count", "—"),
            entry.get("store.size", "—"),
            f"[{health_color}]{health}[/{health_color}]",
        )

    console.print(table)
    console.print(f"[dim]Current INDEX pattern: '{INDEX}' — update the INDEX constant if needed.[/dim]")


def match_all_sample(time_range: str = "now-24h", limit: int = 3) -> None:
    """Fire a plain match_all to confirm data exists and show actual field names."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}]}},
    }
    params = {"path": f"{INDEX}/_search", "method": "POST"}

    console.print(f"[dim]match_all against '{INDEX}' ({time_range}, limit {limit})...[/dim]")
    raw = query_opensearch(body, params)
    if raw is None:
        return

    total = raw.get("hits", {}).get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    console.print(f"[bold]Total hits:[/bold] {total_val}")

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        console.print(
            "[yellow]No hits — index pattern may not match any indices, or no data in this time range.[/yellow]"
        )
        return

    for i, hit in enumerate(hits, 1):
        console.print(f"\n[bold cyan]── Hit {i} ──[/bold cyan]")
        console.print(json.dumps(hit.get("_source", {}), indent=2, default=str))


# ---------------------------------------------------------------------------
# ZeekModule base class
# ---------------------------------------------------------------------------

class ZeekModule:
    """Protocol module interface. Subclass and override methods as needed."""

    DATASETS: list = ["all"]
    SOURCE_FIELDS: list = []
    DETAIL_FIELDS: list = []  # List of (label: str, value_fn: Callable[[dict], str])

    def build_extra_must(self, search_params: dict) -> list:
        """Return protocol-specific must clauses built from search_params."""
        return []

    def parse_hit(self, src: dict) -> dict:
        """Convert an OpenSearch _source dict to a normalised record dict.

        Must include at minimum: timestamp, sensor, src_ip, dest_ip,
        dest_port, src_port, _raw.
        """
        raise NotImplementedError

    def dedup_key(self, record: dict) -> tuple:
        """Return the grouping key tuple for deduplicate_zeek."""
        raise NotImplementedError

    def display(self, records: list) -> None:
        """Render records as a Rich table."""
        raise NotImplementedError

    def display_detail(self, record: dict, idx: int) -> None:
        """Render a Rich Panel with every DETAIL_FIELDS field for the selected record."""
        from rich.panel import Panel
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True, min_width=12)
        grid.add_column(overflow="fold")
        for label, fn in self.DETAIL_FIELDS:
            grid.add_row(label, fn(record))
        console.print(Panel(
            grid,
            title=f"[bold]#{idx}[/bold]  {self.describe_record(record)}",
            expand=False,
        ))

    def add_args(self, parser) -> None:
        """Add protocol-specific argparse arguments to the shared parser."""
        pass

    def describe_record(self, record: dict) -> str:
        """One-line summary used in the interactive loop hint line."""
        src = record.get("src_ip", "?")
        dst = record.get("dest_ip", "?")
        port = record.get("dest_port", "?")
        return f"{src} → {dst}:{port}"

    def fp_signature(self, record: dict) -> str:
        """Signature string embedded in the FP alert dict."""
        return "zeek/unknown"

    def fp_action(self, record: dict) -> None:
        """Handle the [f]alse positive action. Override for custom behaviour."""
        from src.querier.fp_manager import create_filter_interactive
        fp_alert = {
            "src_ip":    record.get("src_ip"),
            "dest_ip":   record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "alert": {
                "signature": self.fp_signature(record),
                "severity":  3,
            },
            "clientID": (record.get("sensors") or [record.get("sensor", "")])[0],
        }
        create_filter_interactive(alert=fp_alert)

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        """Prompt for protocol-specific re-search parameters.

        Override to append module-specific fields to `new`.
        `_ask(label, current_val)` returns the user-entered string or the
        current value's string form if the user pressed Enter.
        """
        pass
