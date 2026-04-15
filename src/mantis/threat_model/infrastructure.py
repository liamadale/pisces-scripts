"""Generate the infrastructure IP registry from ticket data."""

import os

from src.mantis.threat_model._shared import (
    _PROGRESS_INTERVAL,
    _extract_attack_types,
    _extract_protocols,
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
from src.utils.cache import dump_json
from src.utils.ip_org import lookup_org


def generate_infra_registry(
    tickets: list[dict],
    output_path: str,
    provider: OfflineEnrichmentProvider,
    exclude_ips: frozenset[str] = frozenset(),
) -> None:
    """Build known_infra_ips.json from BENIGN_TRUE_POSITIVE tickets.

    Only IPs from tickets classified as BENIGN_TRUE_POSITIVE (authorized scanners,
    CDN, gov probes) are included. Each entry aggregates protocols observed and
    attack contexts (ticket summaries) across all tickets referencing that IP.

    Public IPs must have an identified actor to be included — IPs that merely
    appeared as destinations in benign-scanner tickets are not themselves
    infrastructure and would pollute the registry with unclassified noise.

    Args:
        exclude_ips: Set of IPs already confirmed malicious. These are skipped
            in all passes to eliminate malicious/infra cross-contamination.
    """
    resolved_statuses = {"resolved", "closed"}
    ip_records: dict[str, dict] = {}
    processed = 0
    skipped_malicious = 0
    skipped_no_actor = 0

    console.print(
        f"[dim]  Infra registry: processing {len(tickets):,} tickets...[/dim]"
    )
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        processed += 1
        if processed % _PROGRESS_INTERVAL == 0:
            _progress("Infra", processed, len(tickets))

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        if result.disposition != Disposition.BENIGN_TRUE_POSITIVE:
            continue
        if result.actor == Actor.CISA_CYHY:
            continue  # CISA routed to FP list instead
        if result.actor == Actor.DNS_RESOLVER:
            continue  # DNS resolvers routed to dns resolver registry instead

        admin_note_text = "\n".join(
            n["text"] for n in ticket.get("notes", []) if n.get("is_admin_note")
        )
        # activity_text: fields describing directly observed events — used for
        # attack_types to avoid enrichment API blobs inflating the category list.
        activity_text = "\n".join(
            filter(
                None,
                [
                    ticket.get("summary", ""),
                    ticket.get("steps_to_reproduce", ""),
                ],
            )
        )
        all_text = "\n".join(
            filter(
                None,
                [
                    ticket.get("summary", ""),
                    ticket.get("description", ""),
                    ticket.get("steps_to_reproduce", ""),
                    ticket.get("additional_information", ""),
                    admin_note_text,
                ],
            )
        )

        protocols = _extract_protocols(all_text)
        attack_types = _extract_attack_types(activity_text)
        ticket_id = str(ticket["id"])
        created = ticket.get("created_at", "")
        updated = ticket.get("updated_at") or ticket.get("last_updated") or ""
        summary = ticket.get("summary", "")
        actor_val = result.actor.value if result.actor else None

        for ip in ticket.get("ips", []):
            # Never admit IPs confirmed as malicious threats.
            if ip in exclude_ips:
                skipped_malicious += 1
                continue
            # Public IPs must have an identified actor — destination IPs that
            # merely appeared in a benign-scanner ticket carry no useful
            # infrastructure signal on their own.
            if _is_public(ip) and actor_val is None:
                skipped_no_actor += 1
                continue
            if ip not in ip_records:
                ip_records[ip] = {
                    "ip": ip,
                    "org": lookup_org(ip),
                    "actor": actor_val,
                    "first_seen": created,
                    "last_seen": updated,
                    "ticket_ids": [],
                    "protocols_seen": [],
                    "attacks_against": [],
                }

            rec = ip_records[ip]
            if ticket_id not in rec["ticket_ids"]:
                rec["ticket_ids"].append(ticket_id)

            rec["protocols_seen"] = sorted(set(rec["protocols_seen"]) | set(protocols))
            if not rec["actor"] and actor_val:
                rec["actor"] = actor_val

            if created and (not rec["first_seen"] or created < rec["first_seen"]):
                rec["first_seen"] = created
            if updated and (not rec["last_seen"] or updated > rec["last_seen"]):
                rec["last_seen"] = updated

            # attacks_against — cap at 10, no duplicate ticket_ids
            if attack_types and len(rec["attacks_against"]) < 10:
                existing = {a["ticket_id"] for a in rec["attacks_against"]}
                if ticket_id not in existing:
                    rec["attacks_against"].append(
                        {
                            "ticket_id": ticket_id,
                            "attack_types": attack_types,
                            "summary": summary[:200],
                        }
                    )

    # Second pass: private IPs from any resolved/closed ticket → infra registry
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        ticket_id = str(ticket["id"])
        admin_note_text = "\n".join(
            n["text"] for n in ticket.get("notes", []) if n.get("is_admin_note")
        )
        all_text = "\n".join(
            filter(
                None,
                [
                    ticket.get("summary", ""),
                    ticket.get("description", ""),
                    ticket.get("steps_to_reproduce", ""),
                    ticket.get("additional_information", ""),
                    admin_note_text,
                ],
            )
        )
        for ip in ticket.get("private_ips") or []:
            if ip not in ip_records:
                ip_records[ip] = {
                    "ip": ip,
                    "org": "internal",
                    "actor": "internal_infrastructure",
                    "first_seen": ticket.get("created_at", ""),
                    "last_seen": (
                        ticket.get("updated_at") or ticket.get("last_updated") or ""
                    ),
                    "ticket_ids": [],
                    "protocols_seen": [],
                    "attacks_against": [],
                }
            rec = ip_records[ip]
            if ticket_id not in rec["ticket_ids"]:
                rec["ticket_ids"].append(ticket_id)
            rec["protocols_seen"] = sorted(
                set(rec["protocols_seen"]) | set(_extract_protocols(all_text))
            )

    _progress("Infra done", processed, len(tickets))

    if skipped_malicious:
        console.print(
            f"[dim]  Skipped {skipped_malicious} IP occurrences already in malicious registry[/dim]"
        )
    if skipped_no_actor:
        console.print(
            f"[dim]  Skipped {skipped_no_actor} public IP occurrences with no actor attribution[/dim]"
        )

    for rec in ip_records.values():
        rec["ticket_ids"] = sorted(set(rec["ticket_ids"]))

    records = sorted(ip_records.values(), key=lambda r: r["ip"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    dump_json(records, tmp)
    os.rename(tmp, output_path)

    console.print(f"[green]Infra registry: {len(records)} IPs → {output_path}[/green]")
