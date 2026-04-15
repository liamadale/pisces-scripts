"""Generate the undetermined IP registry and run API enrichment pass."""

import ipaddress
import os

from src.mantis.threat_model._shared import (
    _PROGRESS_INTERVAL,
    _progress,
    console,
)
from src.mantis.ticket_enrichment import (
    Disposition,
    OfflineEnrichmentProvider,
    classify_rules,
)
from src.utils.cache import dump_json, load_json
from src.utils.ip_org import lookup_org


def generate_undetermined_registry(
    tickets: list[dict],
    output_path: str,
    provider: OfflineEnrichmentProvider,
) -> None:
    """Build undetermined_ips.json from tickets the classifier could not resolve.

    Captures IPs from resolved/closed tickets with UNDETERMINED disposition
    for manual review. Entries include the classifier score and signals to aid
    triage.
    """
    resolved_statuses = {"resolved", "closed"}
    ip_data: dict[str, dict] = {}
    processed = 0

    console.print(f"[dim]  Undetermined registry: processing {len(tickets):,} tickets...[/dim]")
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        processed += 1
        if processed % _PROGRESS_INTERVAL == 0:
            _progress("Undetermined", processed, len(tickets))

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        if result.disposition != Disposition.UNDETERMINED:
            continue

        for ip in ticket["ips"]:
            if ip not in ip_data:
                ip_data[ip] = {
                    "score": result.score,
                    "signals": result.signals,
                    "ticket_ids": [],
                }
            else:
                if result.score > ip_data[ip]["score"]:
                    ip_data[ip]["score"] = result.score
                    ip_data[ip]["signals"] = result.signals
            ip_data[ip]["ticket_ids"].append(ticket["id"])

    _progress("Undetermined done", processed, len(tickets))

    records = [
        {
            "ip": ip,
            "org": lookup_org(ip),
            "score": d["score"],
            "signals": d["signals"],
            "ticket_ids": sorted(set(d["ticket_ids"])),
        }
        for ip, d in sorted(ip_data.items())
    ]

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    dump_json(records, tmp)
    os.rename(tmp, output_path)

    console.print(f"[green]Undetermined registry: {len(records)} IPs → {output_path}[/green]")


def enrich_undetermined_ips(
    undetermined_path: str,
    provider: OfflineEnrichmentProvider,
) -> None:
    """Query GreyNoise and AbuseIPDB for each unique IP in undetermined_ips.json.

    Only IPs without a fresh cache entry are queried — the enrichment cache
    (30-day TTL) prevents redundant API calls across runs.  Results are stored
    in the provider's in-memory cache and flushed to disk after every IP so
    that partial runs are not wasted.

    Paid API calls are gated to public IPs only (no point querying RFC1918).
    Skips gracefully if no undetermined file exists yet.
    """
    if not os.path.exists(undetermined_path):
        console.print("[dim]  No undetermined registry found — skipping API enrichment.[/dim]")
        return

    undetermined: list[dict] = load_json(undetermined_path)  # type: ignore[assignment]

    # Collect unique public IPs that need enrichment
    ips_to_enrich: list[str] = []
    seen: set[str] = set()
    for rec in undetermined:
        ip = rec.get("ip", "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        # Skip non-public addresses (matches _is_public logic in _shared.py)
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
                continue
        except ValueError:
            continue
        # Skip if already cached
        if provider.has_fresh_api_cache(ip):
            continue
        ips_to_enrich.append(ip)

    if not ips_to_enrich:
        console.print("[dim]  All undetermined IPs already have fresh cache entries.[/dim]")
        return

    console.print(
        f"[cyan]  Enriching {len(ips_to_enrich)} undetermined IPs via paid APIs...[/cyan]"
    )

    # Import here to avoid circular dependency and ensure .env is loaded
    from src.enricher import abuseipdb as _ab  # noqa: PLC0415
    from src.enricher import greynoise as _gn  # noqa: PLC0415

    for i, ip in enumerate(ips_to_enrich, 1):
        console.print(f"[dim]  [{i}/{len(ips_to_enrich)}] {ip}...[/dim]", end="")
        try:
            gn_result = _gn.check_ip(ip)
        except Exception as exc:  # noqa: BLE001
            console.print(f" [yellow]GreyNoise failed: {exc}[/yellow]")
            gn_result = None

        try:
            ab_result = _ab.check_ip(ip)
        except Exception as exc:  # noqa: BLE001
            console.print(f" [yellow]AbuseIPDB failed: {exc}[/yellow]")
            ab_result = None

        provider.save_api_result(ip, greynoise=gn_result, abuseipdb=ab_result)

        gn_class = (gn_result or {}).get("classification", "?")
        ab_score = (ab_result or {}).get("score")
        ab_str = f"{ab_score}%" if ab_score is not None else "—"
        console.print(f" GN={gn_class} AbuseIPDB={ab_str}")

    console.print(f"[green]  API enrichment complete ({len(ips_to_enrich)} IPs).[/green]")
