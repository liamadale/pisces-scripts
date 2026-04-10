"""Generate the false positive candidate IP registry from ticket data."""

import json
import os

from src.mantis.threat_model._shared import (
    _PROGRESS_INTERVAL,
    _get_ip_roles,
    _is_public,
    _progress,
    console,
)
from src.mantis.ticket_enrichment import (
    Actor,
    Disposition,
    OfflineEnrichmentProvider,
    classify_rules,
)
from src.utils.ip_org import lookup_org


def generate_fp_candidates(
    tickets: list[dict],
    fp_output: str,
    provider: OfflineEnrichmentProvider,
) -> None:
    """Write scored FP candidate IPs from resolved/closed tickets.

    Only includes IPs from tickets with a positive FP score and no disqualifying
    malicious signals. Outputs a categorized JSON file at fp_output.
    """
    resolved_statuses = {"resolved", "closed"}

    # ip → {disposition, threat_type, actor, score, ticket_ids}
    ip_data: dict[str, dict] = {}
    disposition_counts: dict[str, int] = {}
    processed = 0

    console.print(f"[dim]  FP candidates: processing {len(tickets):,} tickets...[/dim]")
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        processed += 1
        if processed % _PROGRESS_INTERVAL == 0:
            _progress("FP", processed, len(tickets))

        # Use pre-computed roles from the index (falls back to regex+NLP for old files).
        fp_source_ips, fp_dest_ips = _get_ip_roles(ticket)

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        disp_key = result.disposition.value
        disposition_counts[disp_key] = disposition_counts.get(disp_key, 0) + 1

        if result.disposition == Disposition.TRUE_POSITIVE:
            continue
        if result.disposition == Disposition.UNDETERMINED:
            continue  # undetermined tickets go to undetermined_ips.json
        if result.disposition == Disposition.BENIGN_TRUE_POSITIVE:
            if result.actor != Actor.CISA_CYHY:
                continue  # non-CISA infra goes to infra registry, not FP
            # CISA falls through to FP collection
        if result.score < 50:
            continue
        # Reject entries whose sole basis for the FP verdict is the local
        # prior from the previous run.  A local_prior of "false_positive"
        # raises the base reputation from 50 → 70, which just meets the FP
        # threshold — but that signal originates from the previous model run,
        # not from any evidence in the current ticket.  Accepting it without
        # additional corroboration creates a self-reinforcing feedback loop
        # where borderline historical decisions are locked in forever.
        # Require at least one current-ticket signal alongside the prior.
        if result.signals == ["local_prior: false_positive"]:
            continue

        for ip in ticket["ips"]:
            if not _is_public(ip):
                continue
            if ip in fp_source_ips:
                fp_role: str | None = "source"
            elif ip in fp_dest_ips:
                fp_role = "dest"
            else:
                fp_role = None

            if ip not in ip_data:
                ip_data[ip] = {
                    "disposition": disp_key,
                    "threat_type": result.threat_type.value
                    if result.threat_type
                    else None,
                    "actor": result.actor.value if result.actor else None,
                    "score": result.score,
                    "country": provider.get_country(ip),
                    "role": fp_role,
                    "ticket_ids": [],
                }
            else:
                # Upgrade if this ticket is stronger evidence
                if result.score > ip_data[ip]["score"]:
                    ip_data[ip]["disposition"] = disp_key
                    ip_data[ip]["threat_type"] = (
                        result.threat_type.value if result.threat_type else None
                    )
                    ip_data[ip]["actor"] = result.actor.value if result.actor else None
                    ip_data[ip]["score"] = result.score
                # Backfill country if not yet set
                if not ip_data[ip].get("country"):
                    ip_data[ip]["country"] = provider.get_country(ip)
                # Upgrade role to source if confirmed (source > dest > None)
                if fp_role == "source" and ip_data[ip].get("role") != "source":
                    ip_data[ip]["role"] = "source"
                elif fp_role == "dest" and ip_data[ip].get("role") is None:
                    ip_data[ip]["role"] = "dest"
            ip_data[ip]["ticket_ids"].append(ticket["id"])

    _progress("FP done", processed, len(tickets))

    os.makedirs(os.path.dirname(fp_output), exist_ok=True)

    detail = [
        {
            "ip": ip,
            "org": lookup_org(ip),
            "disposition": d["disposition"],
            "threat_type": d["threat_type"],
            "actor": d["actor"],
            "score": d["score"],
            "country": d.get("country"),
            "role": d.get("role"),
            "ticket_ids": sorted(set(d["ticket_ids"])),
        }
        for ip, d in sorted(ip_data.items())
    ]
    with open(fp_output, "w") as fh:
        json.dump(detail, fh, indent=2)

    console.print(f"[green]FP candidates: {len(ip_data)} IPs → {fp_output}[/green]")
    console.print("[dim]  Ticket disposition breakdown:[/dim]")
    for disp, count in sorted(disposition_counts.items(), key=lambda x: -x[1]):
        console.print(f"[dim]    {count:5d}  {disp}[/dim]")
