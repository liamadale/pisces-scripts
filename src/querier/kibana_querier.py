#!/usr/bin/env python3
"""
PISCES SOC Analyst Tool — Kibana Querier

Entry point for querying Suricata alert data from Kibana with pre-query
false positive filtering via YAML-defined must_not clauses.

Usage:
    python src/querier/kibana_querier.py --help
    python src/querier/kibana_querier.py --time-range now-24h --severity 2 --cities all --public-only
"""

import argparse
import ipaddress
import json
import os
import readline  # noqa: F401 — enables arrow-key history and suppresses escape echoing in input()
import sys
from collections import defaultdict

import requests
import urllib3
from dotenv import load_dotenv

# The lab Kibana and Mantis instances use self-signed certs; suppress the
# per-request InsecureRequestWarning that would otherwise spam every request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.filter_loader import load_filters
from src.utils.dns import setup_dns

console = Console()

def _make_banner() -> Text:
    _BODY_SPLIT = 21  # blue | red boundary for lines 3-13
    _TEXT_SPLIT = 57  # red | green boundary for lines 6-13
    _TAIL_SPLIT = 31  # blue | red boundary for lines 14-17

    _lines = [
        "\n"
        # 0-2: pure blue
        "              ███████",
        "          ███████████",
        # 2-5: blue | red
        "        ████████ ████    ████████████",
        "      ███████████████  ███████     ██████",
        "     ███████████████     ███         ██████",
        "  █████████████████                   █  ████",
        # 6-13: blue | red | green
        " ██ ████████   ███                     █ █████           ██████████    ██     █████████     ██████████   ██████████    █████████",
        "███████████   ███                      █  █████          ██       ██   ██   ███           ███       ██   ██          ███",
        "██████████   ████                      █  ██████         ██       ███  ██   ███          ██              ██          ███",
        "█████████   ██ █                       █  ██████   █     ██       ██   ██     ██████     ██              █████████     ██████",
        "   ██████  ██                      ██ █   ██████ ███     ██████████    ██           ███  ██              ██                  ███",
        "    █████  ██                     █████   ██████ ███     ██            ██            ██  ███        ██   ██                   ██",
        "    █████  ██                     ███    ███████ ██      ██            ██   ████    ███    ████   ████   ██          ████    ███",
        "     █████ ██                     ███   ██████████       ██            ██      █████          █████      ██████████     █████",
        # 14-17: blue | red
        "       ████ ██                  ███████████████ █",
        "        ███████         ███    ███████████████",
        "           █████      ███████  ██████████████",
        "              █████████████    ████ ████████",
        # 18-19: pure red
        "                               ██████████",
        "                               ███████",
    ]

    t = Text()
    for i, line in enumerate(_lines):
        if i < 2:
            t.append(line, style="blue")
        elif i < 6:
            t.append(line[:_BODY_SPLIT], style="blue")
            t.append(line[_BODY_SPLIT:], style="red")
        elif i < 14:
            t.append(line[:_BODY_SPLIT], style="blue")
            t.append(line[_BODY_SPLIT:_TEXT_SPLIT], style="red")
            t.append(line[_TEXT_SPLIT:], style="white")
        elif i < 18:
            t.append(line[:_TAIL_SPLIT], style="blue")
            t.append(line[_TAIL_SPLIT:], style="red")
        else:
            t.append(line, style="red")
        t.append("\n")
    return t

BANNER = _make_banner()

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
FILTERS_DIR = os.path.join(_BASE, "filters")

KIBANA_URL = "https://wa-kibana.cyberrangepoulsbo.com/api/console/proxy"
INDEX = "suricata*"

# Common Kibana date-math time ranges shown in help and the re-search prompt
TIME_RANGES = [
    "now-15m", "now-30m",
    "now-1h",  "now-3h",  "now-6h", "now-12h",
    "now-24h", "now-2d",  "now-3d", "now-7d",
    "now-14d", "now-30d",
]

# Suricata severity → Rich color
SEVERITY_COLORS = {1: "red", 2: "yellow", 3: "cyan"}

# RFC 1918 + loopback CIDRs — used as ES term queries against an ip-mapped field
_PRIVATE_CIDRS = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in _PRIVATE_CIDRS)
    except ValueError:
        return False


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
    """Build the Elasticsearch query and params.

    Returns:
        (query_body, request_params)
    """
    must_clauses: list[dict] = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
    ]

    # Severity filter: Suricata severity 1=high, so we want severity <= requested level
    must_clauses.append({"range": {"alert.severity": {"lte": severity}}})

    if cities and cities != ["all"]:
        must_clauses.append({"terms": {"clientID": cities}})

    if public_only:
        must_not = list(must_not)  # copy to avoid mutating caller's list
        for cidr in _PRIVATE_CIDRS:
            # ES ip-typed fields accept CIDR notation in term queries directly
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
# Kibana request
# ---------------------------------------------------------------------------

def query_kibana(body: dict, params: dict) -> dict | None:
    username = os.environ.get("KIBANA_USERNAME", "")
    password = os.environ.get("KIBANA_PASSWORD", "")

    if not username or not password:
        console.print("[red]KIBANA_USERNAME and KIBANA_PASSWORD must be set in .env[/red]")
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
        console.print("[red]Kibana authentication failed — check KIBANA_USERNAME/PASSWORD[/red]")
        return None

    if not resp.ok:
        console.print(f"[red]Kibana error {resp.status_code}: {resp.text[:300]}[/red]")
        return None

    return resp.json()


# ---------------------------------------------------------------------------
# Result processing
# ---------------------------------------------------------------------------

def parse_hits(raw: dict) -> list[dict]:
    """Extract and flatten hits from ES response."""
    hits = raw.get("hits", {}).get("hits", [])
    results = []
    for hit in hits:
        src = hit.get("_source", {})
        results.append({
            "timestamp": src.get("@timestamp", ""),
            "city": src.get("clientID", ""),
            "signature": src.get("alert", {}).get("signature", ""),
            "severity": src.get("alert", {}).get("severity", 3),
            "src_ip": src.get("src_ip", ""),
            "src_port": src.get("src_port"),
            "dest_ip": src.get("dest_ip", ""),
            "dest_port": src.get("dest_port"),
            "proto": src.get("app_proto", ""),
            "bytes_toserver": src.get("flow", {}).get("bytes_toserver"),
            "bytes_toclient": src.get("flow", {}).get("bytes_toclient"),
            "flow_id": src.get("flow_id"),
            # Keep raw for enrichment / ticket seeding
            "_raw": src,
        })
    return results


def deduplicate(alerts: list[dict]) -> list[dict]:
    """Deduplicate by (src_ip, signature), counting frequency."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for alert in alerts:
        key = (alert["src_ip"], alert["signature"])
        grouped[key].append(alert)

    deduped = []
    for (src_ip, signature), group in sorted(
        grouped.items(), key=lambda kv: -len(kv[1])
    ):
        # Take the most recent entry as representative
        rep = sorted(group, key=lambda a: a["timestamp"], reverse=True)[0].copy()
        rep["freq"] = len(group)
        # Collect unique cities
        rep["cities"] = sorted({a["city"] for a in group if a.get("city")})
        deduped.append(rep)

    return deduped


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def _fmt_bytes(b: int | None) -> str:
    """Format a byte count as a human-readable string (B/KB/MB/GB), or '—'."""
    if b is None:
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1000:
            return f"{b:.1f}{unit}"
        b /= 1000
    return f"{b:.1f}PB"


def _sig_col_budget(alerts: list[dict]) -> int:
    """Estimate characters available to the Signature column at current terminal width.

    Sums the natural content widths of every other column (from actual data),
    adds Rich's default padding (2 chars per column) and separator overhead,
    and subtracts from the terminal width.
    """
    def _maxlen(vals) -> int:
        return max((len(str(v)) for v in vals if v is not None), default=0)

    col_content_widths = [
        3,   # #
        16,  # Timestamp (YYYY-MM-DD HH:MM)
        _maxlen(", ".join(a.get("cities") or [a.get("city", "")]) for a in alerts),  # City
        3,   # Sev
        _maxlen(a["freq"] for a in alerts),   # Freq
        _maxlen(a.get("src_ip", "") for a in alerts),   # Src IP
        _maxlen(a.get("src_port") for a in alerts),     # Port (src)
        7,   # →Srv  ("999.9MB")
        _maxlen(a.get("dest_ip", "") for a in alerts),  # Dst IP
        _maxlen(a.get("dest_port") for a in alerts),    # Port (dst)
        5,   # Proto
        7,   # →Cli
        _maxlen(a.get("flow_id") for a in alerts),      # Flow ID
    ]
    n_cols = len(col_content_widths) + 1  # +1 for Signature itself
    # Rich default padding: 1 char each side per column = 2 * n_cols
    # Column separators (SIMPLE_HEAVY): approximately n_cols + 1
    overhead = 2 * n_cols + n_cols + 1
    return max(console.size.width - sum(col_content_widths) - overhead, 5)


def display_alerts(alerts: list[dict]) -> None:
    total = sum(a["freq"] for a in alerts)
    console.print(
        f"\n[bold]Found {len(alerts)} unique alert(s) across {total} raw event(s)[/bold] "
        f"(sorted by frequency)\n"
    )

    # Decide whether signatures fit inline or need a footnote block.
    # Footnote mode kicks in when any signature would wrap more than twice.
    sig_budget = _sig_col_budget(alerts)
    max_sig_len = max((len(a["signature"]) for a in alerts), default=0)
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

    for idx, alert in enumerate(alerts, 1):
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
            str(alert["freq"]),
            alert["src_ip"],
            str(alert["src_port"]) if alert.get("src_port") is not None else "—",
            _fmt_bytes(alert.get("bytes_toserver")),
            alert["dest_ip"],
            str(alert["dest_port"]) if alert.get("dest_port") is not None else "—",
            alert.get("proto") or "—",  # keyed from app_proto
            _fmt_bytes(alert.get("bytes_toclient")),
            str(alert["flow_id"]) if alert.get("flow_id") is not None else "—",
        ]
        table.add_row(*row)

    console.print(table)

    if footnote_mode:
        console.print("[dim]Signatures:[/dim]")
        for idx, alert in enumerate(alerts, 1):
            console.print(f"  [dim]{idx:>3}[/dim]  {alert['signature']}")


# ---------------------------------------------------------------------------
# Interactive post-display prompt
# ---------------------------------------------------------------------------

def _confirm_exit() -> bool:
    """Ask the analyst to confirm exit. Returns True if confirmed."""
    console.print("\n  [bold red]CTRL+C[/bold red] again to exit / [bold green]Enter[/bold green] to continue", end=" ")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        print()
        return True
    return False


def _prompt(text: str) -> str:
    """input() wrapper that raises SystemExit cleanly on Ctrl+C / EOF."""
    try:
        return input(text)
    except EOFError:
        return ""
    except KeyboardInterrupt:
        console.print("")  # move off the input line
        raise


def interactive_loop(alerts: list[dict], search_params: dict) -> None:
    """Prompt analyst for actions on each displayed alert.

    readline is imported at module level which:
      - suppresses raw escape sequences (^[[A, ^[[D, etc.) from being echoed
      - enables up/down arrow history across all input() calls
    """
    # Lazy imports — only needed if analyst chooses to act
    from src.enricher.threat_intel import enrich_ip
    from src.querier.fp_manager import create_filter_interactive
    from src.mantis.mantis_search import search as mantis_search, display_results as display_mantis
    from src.mantis.mantis_submit import submit_interactive

    last_alert: dict | None = None

    while True:
        if last_alert:
            a = last_alert["alert"]
            console.print(
                f"[dim]↩  Last: #{last_alert['idx']} {a['signature']} | {a['src_ip']}[/dim]"
            )
        console.print("\n[bold cyan]Action[/bold cyan] — enter alert # / \\[r]e-search / \\[p]rint (CTRL+C to exit):")
        try:
            raw = _prompt("  > ").strip().lower()
        except KeyboardInterrupt:
            if _confirm_exit():
                break
            continue

        if raw in ("r", "research", "search"):
            search_params = _search_again_prompt(search_params)
            new_alerts = _run_query(search_params)
            if new_alerts:
                alerts = new_alerts
                display_alerts(alerts)
            continue

        if raw in ("p", "print"):
            display_alerts(alerts)
            continue

        if not raw:
            continue

        # Add valid-looking inputs to readline history so up-arrow recalls them
        readline.add_history(raw)

        try:
            idx = int(raw) - 1
            if idx < 0:
                raise ValueError
            alert = alerts[idx]
        except (ValueError, IndexError):
            console.print("[red]Invalid selection.[/red]")
            continue

        src_ip = alert["src_ip"]
        console.print(
            f"\n[bold]Alert #{idx + 1}[/bold]: {alert['signature']} | {src_ip}"
        )
        console.print("  \\[e]nrich  \\[f]alse positive  \\[m]antis search  \\[t]icket  \\[s]kip")

        try:
            action = _prompt("  Action: ").strip().lower()
        except KeyboardInterrupt:
            console.print("[dim]Cancelled.[/dim]")
            continue

        # Accept first letter or full word
        key = action[:1]
        if key:
            readline.add_history(action)

        if key == "e":
            enrich_ip(src_ip)
        elif key == "f":
            fp_alert = {
                "src_ip": src_ip,
                "dest_ip": alert["dest_ip"],
                "dest_port": alert["dest_port"],
                "alert": {"signature": alert["signature"], "severity": alert["severity"]},
                "clientID": alert["cities"][0] if alert.get("cities") else alert.get("city", ""),
            }
            create_filter_interactive(alert=fp_alert)
        elif key == "m":
            dest_ip = alert.get("dest_ip", "")
            # Only search public IPs — private addresses appear in hundreds of
            # tickets as victims and produce nothing but noise.
            def _is_public(ip: str) -> bool:
                try:
                    return not ipaddress.ip_address(ip).is_private
                except ValueError:
                    return True
            queries = dict.fromkeys(ip for ip in [src_ip, dest_ip] if ip and _is_public(ip))
            combined: list[dict] = []
            seen_ids: set[str] = set()
            for q in queries:
                console.print(f"[dim]Searching Mantis for '{q}'...[/dim]")
                for r in mantis_search(q, live=True):
                    if r["id"] not in seen_ids:
                        combined.append(r)
                        seen_ids.add(r["id"])
            display_mantis(combined)
        elif key == "t":
            submit_alert = alert.get("_raw", {})
            submit_alert.setdefault("src_ip", src_ip)
            submit_alert.setdefault("dest_ip", alert["dest_ip"])
            submit_alert.setdefault("clientID", alert.get("city", ""))
            submit_interactive(submit_alert)
        elif key in ("s", ""):
            continue
        else:
            # Silently ignore unrecognised input rather than printing a confusing message
            pass

        last_alert = {"idx": idx + 1, "alert": alert}


# ---------------------------------------------------------------------------
# Search-again helpers
# ---------------------------------------------------------------------------

def _run_query(search_params: dict) -> list[dict]:
    """Build + execute query from a params dict, return deduped alerts (empty on error)."""
    # Reload filters from disk on every query so filters written mid-session take effect.
    filter_result = load_filters(FILTERS_DIR)
    must_not = filter_result["must_not"]
    fcount = filter_result["filter_count"]
    console.print(f"[dim]Loading false positive filters...[/dim]")
    console.print(f"[dim]Loaded {fcount} filter file(s) → {len(must_not)} must_not clause(s)[/dim]")
    if filter_result["errors"]:
        for err in filter_result["errors"]:
            console.print(f"[yellow]Filter warning: {err}[/yellow]")

    cities: list[str] | None = None
    if search_params["cities"] and search_params["cities"].lower() != "all":
        cities = [c.strip() for c in search_params["cities"].split(",")]

    body, params = build_query(
        must_not=must_not,
        time_range=search_params["time_range"],
        severity=search_params["severity"],
        cities=cities,
        public_only=search_params["public_only"],
        signature=search_params.get("signature"),
        min_bytes=search_params.get("min_bytes"),
        protocol=search_params.get("protocol"),
        limit=search_params["limit"],
    )

    console.print(f"[dim]Querying Kibana ({search_params['time_range']})...[/dim]")
    raw = query_kibana(body, params)
    if raw is None:
        return []

    import hashlib
    cache_key = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]
    _save_cache(raw, _cache_path(cache_key))

    alerts = parse_hits(raw)
    if not alerts:
        console.print("[yellow]No alerts returned.[/yellow]")
        return []
    return deduplicate(alerts)


def _search_again_prompt(current: dict) -> dict:
    """Interactively prompt for new search parameters. Enter keeps the current value."""
    console.print("\n[bold cyan]New Search Parameters[/bold cyan] [dim](Enter to keep current)[/dim]")
    console.print("[dim]Time ranges: " + "  ".join(TIME_RANGES) + "[/dim]")

    def _ask(label: str, current_val: object) -> str:
        try:
            val = _prompt(f"  {label} [{current_val}]: ").strip()
            return val if val else str(current_val)
        except KeyboardInterrupt:
            console.print("")
            return str(current_val)

    new = dict(current)

    new["time_range"] = _ask("Time range", current["time_range"])

    sev_raw = _ask("Severity 1-3", current["severity"])
    try:
        new["severity"] = max(1, min(3, int(sev_raw)))
    except ValueError:
        new["severity"] = current["severity"]

    new["cities"] = _ask("Cities (comma-sep or 'all')", current["cities"])

    pub_raw = _ask("Public only (y/n)", "y" if current["public_only"] else "n")
    new["public_only"] = pub_raw.lower() in ("y", "yes")

    sig_raw = _ask("Signature filter (blank to clear)", current.get("signature") or "")
    new["signature"] = sig_raw or None

    limit_raw = _ask("Limit", current["limit"])
    try:
        new["limit"] = int(limit_raw)
    except ValueError:
        new["limit"] = current["limit"]

    return new


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _cache_path(args_hash: str) -> str:
    cache_dir = os.path.join(_BASE, "data", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, f"{args_hash}.json")


def _save_cache(data: dict, path: str) -> None:
    try:
        with open(path, "w") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def _load_cache(path: str) -> dict | None:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="PISCES SOC Analyst Tool — Kibana Querier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--time-range", default="now-24h",
                        help="Kibana date-math time range (default: now-24h). "
                             "Available: " + "  ".join(TIME_RANGES))
    parser.add_argument("--severity", type=int, default=3, choices=[1, 2, 3],
                        help="Max Suricata severity to include (1=high, 3=low, default: 3)")
    parser.add_argument("--cities", default="all",
                        help="Comma-separated city/clientID list, or 'all' (default)")
    parser.add_argument("--public-only", action="store_true",
                        help="Exclude private/RFC1918 source IPs")
    parser.add_argument("--signature", help="Filter to alerts matching this signature pattern")
    parser.add_argument("--min-bytes", type=int, help="Minimum bytes_toserver")
    parser.add_argument("--protocol", help="Protocol filter (TCP/UDP/etc.)")
    parser.add_argument("--limit", type=int, default=50, help="Max raw results from ES (default: 50)")
    parser.add_argument("--no-interactive", action="store_true",
                        help="Print results and exit without the interactive prompt")
    parser.add_argument("--use-cache", action="store_true",
                        help="Use cached Kibana response if available")
    parser.add_argument("--dump-query", action="store_true",
                        help="Print the ES query body and exit (for debugging)")
    args = parser.parse_args()

    console.print(BANNER)

    load_dotenv()
    setup_dns()

    # Parse cities
    cities: list[str] | None = None
    if args.cities and args.cities.lower() != "all":
        cities = [c.strip() for c in args.cities.split(",")]

    # Canonical search params dict — passed into interactive loop so [r] can mutate it
    search_params = {
        "time_range": args.time_range,
        "severity": args.severity,
        "cities": args.cities,
        "public_only": args.public_only,
        "signature": args.signature,
        "min_bytes": args.min_bytes,
        "protocol": args.protocol,
        "limit": args.limit,
    }

    # Load filters for the initial fetch / --dump-query
    filter_result = load_filters(FILTERS_DIR)
    console.print("[dim]Loading false positive filters...[/dim]")
    console.print(
        f"[dim]Loaded {filter_result['filter_count']} filter file(s) → "
        f"{len(filter_result['must_not'])} must_not clause(s)[/dim]"
    )
    if filter_result["errors"]:
        for err in filter_result["errors"]:
            console.print(f"[yellow]Filter warning: {err}[/yellow]")

    # Build query (used for --dump-query and initial fetch)
    body, params = build_query(
        must_not=filter_result["must_not"],
        time_range=search_params["time_range"],
        severity=search_params["severity"],
        cities=cities,
        public_only=search_params["public_only"],
        signature=search_params.get("signature"),
        min_bytes=search_params.get("min_bytes"),
        protocol=search_params.get("protocol"),
        limit=search_params["limit"],
    )

    if args.dump_query:
        print(json.dumps(body, indent=2))
        return

    # Cache key based on query body
    import hashlib
    cache_key = hashlib.md5(json.dumps(body, sort_keys=True).encode()).hexdigest()[:10]
    cpath = _cache_path(cache_key)

    raw = None
    if args.use_cache:
        raw = _load_cache(cpath)
        if raw:
            console.print(f"[dim]Using cached response: {cpath}[/dim]")

    if raw is None:
        console.print(f"[dim]Querying Kibana ({search_params['time_range']})...[/dim]")
        raw = query_kibana(body, params)
        if raw is None:
            sys.exit(1)
        _save_cache(raw, cpath)

    # Parse and process
    alerts = parse_hits(raw)
    if not alerts:
        console.print("[yellow]No alerts returned. Filters may be too aggressive or data may be sparse.[/yellow]")
        return

    deduped = deduplicate(alerts)
    display_alerts(deduped)

    if not args.no_interactive:
        interactive_loop(deduped, search_params)


if __name__ == "__main__":
    main()
