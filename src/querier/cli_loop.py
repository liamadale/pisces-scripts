#!/usr/bin/env python3
"""Interactive CLI loop, profile display, and OpenSearch diagnostic helpers."""

import json
import readline  # noqa: F401 — enables arrow-key history in input()
from collections import defaultdict

import httpx
from rich import box
from rich.table import Table

from src.querier.client import (
    INDEX,
    OpenSearchAuthError,
    OpenSearchConnectionError,
    _opensearch_session,
    console,
    query_opensearch,
)
from src.querier.runner import run_query
from src.utils.terminal import confirm_exit, prompt

# ---------------------------------------------------------------------------
# Profile display
# ---------------------------------------------------------------------------


def _walk_clauses(node: dict, acc: list) -> None:
    """DFS walk of an ES profile query node, collecting (type, description, time_ms)."""
    if not isinstance(node, dict):
        return
    time_ms = node.get("time_in_nanos", 0) / 1_000_000
    acc.append((node.get("type", ""), node.get("description", ""), time_ms))
    for child in node.get("children", []):
        _walk_clauses(child, acc)


def display_profile(raw: dict) -> None:
    """Render OpenSearch profile data: per-shard timing and slowest query clauses."""
    profile = raw.get("profile")
    if not profile:
        console.print("[yellow]No profile data in response.[/yellow]")
        return

    shards = profile.get("shards", [])
    if not shards:
        console.print("[yellow]Profile present but no shard data.[/yellow]")
        return

    # --- Shard summary table ---
    shard_table = Table(title="Profile — per-shard timing", box=box.SIMPLE_HEAVY)
    shard_table.add_column("Shard", style="cyan", no_wrap=True)
    shard_table.add_column("Query (ms)", justify="right")
    shard_table.add_column("Fetch (ms)", justify="right")

    total_query_ms = 0.0
    total_fetch_ms = 0.0
    all_clauses: list = []

    for shard in shards:
        shard_id = shard.get("id", "?")
        query_ms = 0.0
        fetch_ms = 0.0

        for search in shard.get("searches", []):
            for q in search.get("query", []):
                query_ms += q.get("time_in_nanos", 0) / 1_000_000
                _walk_clauses(q, all_clauses)
            for collector in search.get("collector", []):
                fetch_ms += collector.get("time_in_nanos", 0) / 1_000_000

        total_query_ms += query_ms
        total_fetch_ms += fetch_ms
        shard_table.add_row(shard_id, f"{query_ms:.2f}", f"{fetch_ms:.2f}")

    shard_table.add_section()
    shard_table.add_row(
        "[bold]Total[/bold]",
        f"[bold]{total_query_ms:.2f}[/bold]",
        f"[bold]{total_fetch_ms:.2f}[/bold]",
    )
    console.print(shard_table)

    # --- Slowest clauses table (top 15, aggregated across shards) ---
    clause_totals: dict = defaultdict(float)
    clause_types: dict = {}
    for ctype, desc, ms in all_clauses:
        key = desc or ctype
        clause_totals[key] += ms
        clause_types[key] = ctype

    top = sorted(clause_totals.items(), key=lambda kv: -kv[1])[:15]
    if top:
        clause_table = Table(
            title="Profile — slowest clauses (all shards combined)", box=box.SIMPLE_HEAVY
        )
        clause_table.add_column("Type", style="dim", no_wrap=True)
        clause_table.add_column("Description", overflow="fold")
        clause_table.add_column("Total (ms)", justify="right")
        for desc, ms in top:
            clause_table.add_row(clause_types.get(desc, ""), desc, f"{ms:.2f}")
        console.print(clause_table)


# ---------------------------------------------------------------------------
# Search-again prompt
# ---------------------------------------------------------------------------


def _search_again_prompt(current: dict, module) -> dict:
    """Prompt for new search parameters, shared + module-specific."""
    from src.querier.builder import TIME_RANGES

    console.print(
        "\n[bold cyan]New Search Parameters[/bold cyan] [dim](Enter to keep current)[/dim]"
    )
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
    if module.SENSOR_PARAM is not None:
        new[module.SENSOR_PARAM] = _ask(
            "Sensor (comma-sep or 'all')", current.get(module.SENSOR_PARAM, "all")
        )

    if module.SUPPORTS_IP_FILTER:
        pub_raw = _ask("Public only (y/n)", "y" if current.get("public_only") else "n")
        new["public_only"] = pub_raw.lower() in ("y", "yes")

        src_raw = _ask("Src IP filter (blank to clear)", current.get("src_ip"))
        new["src_ip"] = src_raw if src_raw else None

    dir_raw = _ask(
        "Direction filter (inbound/outbound/internal/external/blank)",
        current.get("direction"),
    )
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
# Interactive loop
# ---------------------------------------------------------------------------


def interactive_loop(records: list, search_params: dict, module, query_fn=None) -> None:
    """Interactive post-display prompt — dispatch to module for protocol actions.

    query_fn: callable with signature (module, search_params) -> list.
              Defaults to run_query when None.
    """
    _query_fn = query_fn if query_fn is not None else run_query

    from src.enricher.threat_intel import enrich_ip
    from src.mantis.mantis_search import (
        display_results as display_mantis,
    )
    from src.mantis.mantis_search import (
        search as mantis_search,
    )
    from src.mantis.mantis_search import (
        sensor_to_project,
    )

    last_record: dict | None = None

    while True:
        console.print("")
        if last_record:
            r = last_record["record"]
            hint = module.describe_record(r)
            console.print(f"[dim]↩  Last: #{last_record['idx']} {hint}[/dim]")
        console.print(
            "[bold cyan]Action[/bold cyan] — enter record #"
            " / \\[r]e-search / \\[p]rint (CTRL+C to exit):"
        )
        try:
            raw = prompt("  > ").strip().lower()
        except KeyboardInterrupt:
            if confirm_exit():
                break
            continue

        if raw in ("r", "research", "search"):
            search_params = _search_again_prompt(search_params, module)
            new_records = _query_fn(module, search_params)
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

        # Build action menu dynamically based on module capabilities.
        action_parts = []
        if module.SUPPORTS_ENRICHMENT:
            action_parts.append("\\[e]nrich")
        if module.SUPPORTS_FP:
            action_parts.append("\\[f]alse positive")
        action_parts += ["\\[m]antis search", "\\[s]kip"]
        console.print("  " + "  ".join(action_parts))

        try:
            action = prompt("  Action: ").strip().lower()
        except KeyboardInterrupt:
            console.print("[dim]Cancelled.[/dim]")
            continue

        key = action[:1]
        if key:
            readline.add_history(action)

        if key == "e" and module.SUPPORTS_ENRICHMENT:
            hash_val = record.get("sha256") or record.get("md5") or record.get("file_hash")
            if hash_val and not src_ip:
                # Hash-only enrichment (e.g. pe module — no IP).
                from src.enricher.virustotal import check_hash, display_hash

                console.print(f"[dim]Querying VirusTotal for {hash_val[:16]}…[/dim]")
                display_hash(hash_val, check_hash(hash_val))
            elif hash_val:
                # Both hash and IP available — ask which.
                console.print("  \\[h]ash (VirusTotal file lookup)  \\[i]p enrichment")
                try:
                    sub = prompt("  Choice: ").strip().lower()
                except KeyboardInterrupt:
                    console.print("[dim]Cancelled.[/dim]")
                    sub = ""
                if sub.startswith("h"):
                    from src.enricher.virustotal import check_hash, display_hash

                    console.print(f"[dim]Querying VirusTotal for {hash_val[:16]}…[/dim]")
                    display_hash(hash_val, check_hash(hash_val))
                else:
                    enrich_ip(src_ip)
            else:
                enrich_ip(src_ip)
        elif key == "f" and module.SUPPORTS_FP:
            module.fp_action(record)
        elif key == "m":
            dest_ip = record.get("dest_ip", "")
            queries = dict.fromkeys(ip for ip in [src_ip, dest_ip] if ip)
            city = sensor_to_project(record.get("sensor", "all"))
            if city:
                console.print(f"[dim]Filtering Mantis to project '{city}'[/dim]")
            combined: list = []
            seen_ids: set = set()
            for q in queries:
                console.print(f"[dim]Searching Mantis for '{q}'...[/dim]")
                for r in mantis_search(q, city=city):
                    if r["id"] not in seen_ids:
                        combined.append(r)
                        seen_ids.add(r["id"])
            display_mantis(combined)
        last_record = {"idx": idx + 1, "record": record}


# ---------------------------------------------------------------------------
# Diagnostic helpers
# ---------------------------------------------------------------------------


def list_sensors(time_range: str = "now-7d") -> None:
    """Aggregate on host.name and print all known sensors."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
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
    try:
        raw = query_opensearch(body, params)
    except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
        console.print(f"[red]{exc}[/red]")
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
                "filter": [
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
    try:
        raw = query_opensearch(body, params)
    except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
        console.print(f"[red]{exc}[/red]")
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
    try:
        base_url, session = _opensearch_session()
    except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
        console.print(f"[red]{exc}[/red]")
        return

    try:
        resp = session.post(
            base_url + "/api/console/proxy",
            params={
                "path": (
                    "_cat/indices?format=json&s=docs.count:desc"
                    "&h=index,docs.count,store.size,health"
                ),
                "method": "GET",
            },
            timeout=30,
        )
    except httpx.RequestError as exc:
        console.print(f"[red]Cannot reach OpenSearch at {base_url}: {exc}[/red]")
        return

    if not resp.is_success:
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
    console.print(
        f"[dim]Current INDEX pattern: '{INDEX}' — update the INDEX constant if needed.[/dim]"
    )


def match_all_sample(time_range: str = "now-24h", limit: int = 3) -> None:
    """Fire a plain match_all to confirm data exists and show actual field names."""
    body = {
        "size": limit,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [{"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}]}},
    }
    params = {"path": f"{INDEX}/_search", "method": "POST"}

    console.print(f"[dim]match_all against '{INDEX}' ({time_range}, limit {limit})...[/dim]")
    try:
        raw = query_opensearch(body, params)
    except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
        console.print(f"[red]{exc}[/red]")
        return

    total = raw.get("hits", {}).get("total", {})
    total_val = total.get("value", 0) if isinstance(total, dict) else total
    console.print(f"[bold]Total hits:[/bold] {total_val}")

    hits = raw.get("hits", {}).get("hits", [])
    if not hits:
        console.print(
            "[yellow]No hits — index pattern may not match any indices,"
            " or no data in this time range.[/yellow]"
        )
        return

    for i, hit in enumerate(hits, 1):
        console.print(f"\n[bold cyan]── Hit {i} ──[/bold cyan]")
        console.print(json.dumps(hit.get("_source", {}), indent=2, default=str))
