#!/usr/bin/env python3
"""
Mantis threat model generator — reads a local tickets_index.json produced by
mantis_index.py and runs the ticket_enrichment classification pipeline to emit:
  - data/tickets/enriched/false_positive_ips.json  (false-positive candidate IPs)
  - data/tickets/enriched/malicious_ips.json       (confirmed threat intelligence DB)

Usage:
    python src/mantis/mantis_threat_model.py
    python src/mantis/mantis_threat_model.py --input data/tickets/indexed/tickets_index.json
    python src/mantis/mantis_threat_model.py --classify-stats
"""

import argparse
import os
import sys

from dotenv import load_dotenv

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.mantis.threat_model import (
    enrich_undetermined_ips,
    generate_dns_resolver_registry,
    generate_fp_candidates,
    generate_infra_registry,
    generate_threat_db,
    generate_undetermined_registry,
)
from src.mantis.threat_model._shared import _PROGRESS_INTERVAL, console
from src.mantis.ticket_enrichment import (
    Disposition,
    OfflineEnrichmentProvider,
    classify_rules,
)
from src.utils.cache import dump_json, load_json

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Classification stats
# ---------------------------------------------------------------------------


def _print_classify_stats(
    tickets: list[dict],
    provider: OfflineEnrichmentProvider,
) -> None:
    """Print detailed classification breakdown for all tickets."""
    from collections import Counter

    disposition_counts: Counter = Counter()
    threat_type_counts: Counter = Counter()
    actor_counts: Counter = Counter()
    method_counts: Counter = Counter()
    undetermined_with_notes = 0

    console.print(
        f"[dim]  Classify stats: processing {len(tickets):,} tickets...[/dim]"
    )
    for i, ticket in enumerate(tickets, 1):
        if i % _PROGRESS_INTERVAL == 0:
            console.print(
                f"[dim]  classify-stats: {i:,}/{len(tickets):,} tickets[/dim]"
            )

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        disposition_counts[result.disposition.value] += 1
        method_counts[result.method] += 1
        if result.threat_type:
            threat_type_counts[result.threat_type.value] += 1
        if result.actor:
            actor_counts[result.actor.value] += 1
        if result.disposition == Disposition.UNDETERMINED:
            admin_notes = [n for n in ticket.get("notes", []) if n.get("is_admin_note")]
            if admin_notes:
                undetermined_with_notes += 1

    total = len(tickets)
    console.print(f"\n[bold]Classification breakdown ({total} tickets):[/bold]")

    console.print("\n[dim]  By disposition:[/dim]")
    for disp, count in disposition_counts.most_common():
        pct = count / total * 100
        console.print(f"[dim]    {count:5d} ({pct:5.1f}%)  {disp}[/dim]")

    console.print(
        f"\n[dim]  Undetermined with admin notes: {undetermined_with_notes}[/dim]"
    )

    console.print("\n[dim]  Threat type breakdown (true_positive tickets):[/dim]")
    for tt, count in threat_type_counts.most_common():
        console.print(f"[dim]    {count:5d}  {tt}[/dim]")

    console.print("\n[dim]  Actor breakdown (benign_true_positive tickets):[/dim]")
    for actor, count in actor_counts.most_common():
        console.print(f"[dim]    {count:5d}  {actor}[/dim]")

    console.print(f"\n[dim]  By method: {dict(method_counts)}[/dim]")


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------


def _load_ip_set(path: str) -> frozenset[str]:
    """Return a frozenset of all IP strings from a JSON registry file.

    Returns an empty frozenset if the file does not exist yet (first run).
    """
    if not os.path.exists(path):
        return frozenset()
    records: list[dict] = load_json(path)  # type: ignore[assignment]
    return frozenset(r["ip"] for r in records if "ip" in r)


# ---------------------------------------------------------------------------
# Cross-registry conflict resolution
# ---------------------------------------------------------------------------


def _resolve_registry_conflicts(
    threat_path: str,
    fp_path: str,
    undetermined_path: str,
) -> None:
    """Enforce registry exclusivity across all three output registries.

    Step 1 — malicious ∩ FP (genuine disagreement):
        fp_count >= 3 * mal_count  → keep in FP only  (conflict_resolved_fp)
        mal_count >= 3 * fp_count  → keep in malicious only (conflict_resolved_tp)
        otherwise                  → move to undetermined (registry_conflict)

    Step 2 — undetermined ∩ malicious or undetermined ∩ FP:
        Malicious and FP registries take priority over undetermined.  An IP
        that appears in undetermined *and* in a higher-priority registry is
        simply removed from undetermined — the higher-priority verdict wins.

    All three output files are rewritten atomically (write to .tmp, then rename).
    """
    if not (os.path.exists(threat_path) and os.path.exists(fp_path)):
        return

    malicious: list[dict] = load_json(threat_path)  # type: ignore[assignment]
    fp_list: list[dict] = load_json(fp_path)  # type: ignore[assignment]

    mal_by_ip = {r["ip"]: r for r in malicious}
    fp_by_ip = {r["ip"]: r for r in fp_list}

    # --- Step 1: resolve malicious ∩ FP conflicts ---
    conflicted_ips = set(mal_by_ip) & set(fp_by_ip)

    resolved_to_fp: list[str] = []
    resolved_to_mal: list[str] = []
    moved_to_undetermined: list[dict] = []

    for ip in conflicted_ips:
        mal_rec = mal_by_ip[ip]
        fp_rec = fp_by_ip[ip]
        mal_count = mal_rec.get("ticket_count", len(mal_rec.get("ticket_ids", [])))
        fp_count = len(fp_rec.get("ticket_ids", []))

        if fp_count >= 3 * mal_count:
            del mal_by_ip[ip]
            fp_rec.setdefault("signals", [])
            fp_rec["signals"].append("conflict_resolved_fp")
            resolved_to_fp.append(ip)
        elif mal_count >= 3 * fp_count:
            del fp_by_ip[ip]
            mal_rec.setdefault("signals", [])
            mal_rec["signals"].append("conflict_resolved_tp")
            resolved_to_mal.append(ip)
        else:
            del mal_by_ip[ip]
            del fp_by_ip[ip]
            moved_to_undetermined.append(
                {
                    "ip": ip,
                    "org": mal_rec.get("org"),
                    "score": 50,
                    "signals": ["registry_conflict"],
                    "ticket_ids": sorted(
                        set(mal_rec.get("ticket_ids", []))
                        | set(fp_rec.get("ticket_ids", []))
                    ),
                }
            )

    # --- Step 2: purge undetermined IPs that belong to a higher-priority registry ---
    # Load undetermined (may have been written by generate_undetermined_registry).
    existing_undetermined: list[dict] = []
    if os.path.exists(undetermined_path):
        existing_undetermined = load_json(undetermined_path)  # type: ignore[assignment]

    existing_by_ip: dict[str, dict] = {r["ip"]: r for r in existing_undetermined}

    # Merge any mal∩FP conflicts resolved to undetermined in step 1.
    for rec in moved_to_undetermined:
        existing_by_ip[rec["ip"]] = rec

    # Drop undetermined entries whose IP is now confirmed in malicious or FP.
    priority_ips = set(mal_by_ip) | set(fp_by_ip)
    purged_from_undetermined = [ip for ip in list(existing_by_ip) if ip in priority_ips]
    for ip in purged_from_undetermined:
        del existing_by_ip[ip]

    # Rewrite undetermined.
    undetermined_sorted = sorted(existing_by_ip.values(), key=lambda r: r["ip"])
    tmp = undetermined_path + ".tmp"
    dump_json(undetermined_sorted, tmp)
    os.rename(tmp, undetermined_path)

    # --- Rewrite malicious and FP without resolved conflicts ---
    new_malicious = sorted(mal_by_ip.values(), key=lambda r: -r.get("ticket_count", 0))
    tmp = threat_path + ".tmp"
    dump_json(new_malicious, tmp)
    os.rename(tmp, threat_path)

    new_fp = sorted(fp_by_ip.values(), key=lambda r: r["ip"])
    tmp = fp_path + ".tmp"
    dump_json(new_fp, tmp)
    os.rename(tmp, fp_path)

    total_conflicts = len(conflicted_ips)
    if total_conflicts == 0 and not purged_from_undetermined:
        console.print("[dim]  Registry conflict check: no conflicts found.[/dim]")
        return

    if total_conflicts:
        console.print(
            f"[yellow]Registry conflicts resolved: {total_conflicts} mal∩FP IPs[/yellow]"
        )
    if resolved_to_fp:
        console.print(
            f"[dim]  → kept in FP only (conflict_resolved_fp):"
            f" {len(resolved_to_fp)}[/dim]"
        )
    if resolved_to_mal:
        console.print(
            f"[dim]  → kept in malicious only (conflict_resolved_tp):"
            f" {len(resolved_to_mal)}[/dim]"
        )
    if moved_to_undetermined:
        console.print(
            f"[dim]  → moved to undetermined (registry_conflict):"
            f" {len(moved_to_undetermined)}[/dim]"
        )
    if purged_from_undetermined:
        console.print(
            f"[yellow]  Purged {len(purged_from_undetermined)} IPs from undetermined"
            f" (already in malicious or FP registry)[/yellow]"
        )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Read tickets_index.json and emit FP/threat model files."""
    parser = argparse.ArgumentParser(description="PISCES Mantis Threat Model Generator")
    parser.add_argument(
        "--input",
        default=os.path.join(_BASE, "data", "tickets", "indexed", "tickets_index.json"),
        help="Path to tickets_index.json produced by mantis_index.py",
    )
    parser.add_argument(
        "--fp-output",
        default=os.path.join(
            _BASE, "data", "tickets", "enriched", "false_positive_ips.json"
        ),
        help="Output path for FP candidate IPs (JSON)",
    )
    parser.add_argument(
        "--threat-output",
        default=os.path.join(
            _BASE, "data", "tickets", "enriched", "malicious_ips.json"
        ),
        help="Output path for malicious IPs threat database",
    )
    parser.add_argument(
        "--infra-output",
        default=os.path.join(
            _BASE, "data", "tickets", "enriched", "known_infra_ips.json"
        ),
        help="Output path for infrastructure IP registry",
    )
    parser.add_argument(
        "--dns-output",
        default=os.path.join(
            _BASE, "data", "tickets", "enriched", "dns_resolver_ips.json"
        ),
        help="Output path for known public DNS resolver IPs",
    )
    parser.add_argument(
        "--undetermined-output",
        default=os.path.join(
            _BASE, "data", "tickets", "enriched", "undetermined_ips.json"
        ),
        help="Output path for IPs from tickets the classifier could not resolve",
    )
    parser.add_argument(
        "--classify-stats",
        action="store_true",
        help="Print detailed classification breakdown",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        default=False,
        help=(
            "Enable paid API enrichment (GreyNoise + AbuseIPDB) for "
            "UNDETERMINED-zone IPs (score 31–69). Requires GREYNOISE_API_KEY "
            "and/or ABUSEIPDB_API_KEY in the environment. Results are cached "
            "with a 30-day TTL in data/enrichment_cache.json. After enrichment "
            "all registries are regenerated with the updated signals."
        ),
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        console.print(f"[red]Index not found: {args.input}[/red]")
        console.print("[dim]Run mantis_index.py first to build the index.[/dim]")
        sys.exit(1)

    load_dotenv()

    console.print(f"[dim]Loading index from {args.input}...[/dim]")
    tickets = load_json(args.input)
    console.print(f"[dim]Loaded {len(tickets):,} tickets.[/dim]")

    console.print("[dim]Initialising offline enrichment provider...[/dim]")
    provider = OfflineEnrichmentProvider()
    console.print(
        f"[dim]Provider ready — {len(provider._mal_by_ip):,} malicious priors, "
        f"{len(provider._fp_by_ip):,} FP priors, "
        f"{len(provider._ecache):,} cached IPs[/dim]"
    )

    if args.classify_stats:
        _print_classify_stats(tickets, provider)

    generate_fp_candidates(tickets, args.fp_output, provider)
    generate_threat_db(tickets, args.threat_output, provider)
    generate_infra_registry(
        tickets,
        args.infra_output,
        provider,
        exclude_ips=_load_ip_set(args.threat_output),
    )
    generate_dns_resolver_registry(tickets, args.dns_output)
    generate_undetermined_registry(tickets, args.undetermined_output, provider)

    if args.enrich:
        console.print("\n[bold cyan]API enrichment pass (--enrich)[/bold cyan]")
        enrich_undetermined_ips(args.undetermined_output, provider)
        console.print(
            "[dim]Re-running registry generators with enriched signals...[/dim]"
        )
        generate_fp_candidates(tickets, args.fp_output, provider)
        generate_threat_db(tickets, args.threat_output, provider)
        generate_infra_registry(
            tickets,
            args.infra_output,
            provider,
            exclude_ips=_load_ip_set(args.threat_output),
        )
        generate_dns_resolver_registry(tickets, args.dns_output)
        generate_undetermined_registry(tickets, args.undetermined_output, provider)

    _resolve_registry_conflicts(
        args.threat_output, args.fp_output, args.undetermined_output
    )


if __name__ == "__main__":
    main()
