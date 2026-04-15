"""Generate the DNS resolver IP registry from ticket data."""

import os

from src.mantis.threat_model._shared import console
from src.mantis.ticket_enrichment import Actor, is_known_dns_resolver
from src.utils.cache import dump_json
from src.utils.ip_org import lookup_org


def generate_dns_resolver_registry(tickets: list[dict], output_path: str) -> None:
    """Build dns_resolver_ips.json from tickets mentioning known public DNS resolvers.

    Aggregates ticket IDs and summaries for each known resolver IP seen across
    all tickets, regardless of resolution status.
    """
    resolved_statuses = {"resolved", "closed"}
    ip_records: dict[str, dict] = {}

    for ticket in tickets:
        # Consistent with all other registry generators: only finalised tickets
        # contribute to the registry.  Open/in-progress tickets may mention a
        # DNS resolver IP incidentally and should not lock it in before review.
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        ticket_id = str(ticket["id"])
        summary = ticket.get("summary", "")

        for ip in ticket.get("ips", []):
            if not is_known_dns_resolver(ip):
                continue

            if ip not in ip_records:
                ip_records[ip] = {
                    "ip": ip,
                    "org": lookup_org(ip),
                    "actor": Actor.DNS_RESOLVER.value,
                    "ticket_ids": [],
                    "summaries": [],
                }

            rec = ip_records[ip]
            if ticket_id not in rec["ticket_ids"]:
                rec["ticket_ids"].append(ticket_id)
            if (
                summary
                and summary not in rec["summaries"]
                and len(rec["summaries"]) < 5
            ):
                rec["summaries"].append(summary)

    for rec in ip_records.values():
        rec["ticket_ids"] = sorted(set(rec["ticket_ids"]))

    records = sorted(ip_records.values(), key=lambda r: r["ip"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    dump_json(records, tmp)
    os.rename(tmp, output_path)

    console.print(
        f"[green]DNS resolver registry: {len(records)} IPs → {output_path}[/green]"
    )
