"""Generate the malicious IP threat database from ticket data."""

import json
import os
from collections import Counter, defaultdict

from src.mantis.threat_model._shared import (
    _DEST_IP_RE,
    _PROGRESS_INTERVAL,
    _extract_asn,
    _extract_attack_types,
    _extract_blocklists,
    _extract_country_code,
    _extract_isp,
    _extract_usage_type,
    _get_ip_roles,
    _is_public,
    _label_text,
    _progress,
    console,
)
from src.mantis.ticket_enrichment import (
    Disposition,
    OfflineEnrichmentProvider,
    classify_rules,
)
from src.utils.ip_org import lookup_org

# Thresholds for classifying a public IP as a monitored asset (defended
# infrastructure) rather than an external threat actor.  An IP qualifies
# when it appears in many tickets, is predominantly labelled as the
# *destination* (victim), and the majority of those tickets belong to a
# single project (i.e. it's one organization's internet-facing host).
_ASSET_MIN_TICKETS = 15
_ASSET_MIN_DEST_RATIO = 0.40
_ASSET_MIN_PROJECT_SHARE = 0.50


def _build_monitored_assets(tickets: list[dict]) -> frozenset[str]:
    """Identify public IPs that are monitored assets, not threat actors.

    An IP is considered a monitored asset when:
    - It appears in >= ``_ASSET_MIN_TICKETS`` tickets.
    - It is labelled as destination in >= ``_ASSET_MIN_DEST_RATIO``
      of those tickets (high victim ratio).
    - A single project accounts for >= ``_ASSET_MIN_PROJECT_SHARE``
      of those tickets (concentrated ownership).

    These IPs are defended infrastructure that appear in the ticket
    system because they are *targets* of attacks, not the source.
    Tickets may list them as ``source`` for outbound connections
    to suspicious destinations, but the IP itself is not malicious.
    """
    ip_total: dict[str, int] = defaultdict(int)
    ip_as_dst: dict[str, int] = defaultdict(int)
    ip_projects: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for ticket in tickets:
        project = ticket.get("project", "")
        # Prefer pre-computed dest list from index; fall back to regex for old files.
        dsts = set(ticket.get("ip_dest") or _DEST_IP_RE.findall(_label_text(ticket)))

        for ip in ticket.get("ips", []):
            if not _is_public(ip):
                continue
            ip_total[ip] += 1
            ip_projects[ip][project] += 1
            if ip in dsts:
                ip_as_dst[ip] += 1

    assets: set[str] = set()
    for ip, total in ip_total.items():
        if total < _ASSET_MIN_TICKETS:
            continue
        dst_ratio = ip_as_dst.get(ip, 0) / total
        if dst_ratio < _ASSET_MIN_DEST_RATIO:
            continue
        proj_counts = ip_projects[ip]
        dominant_share = max(proj_counts.values()) / total
        if dominant_share < _ASSET_MIN_PROJECT_SHARE:
            continue
        assets.add(ip)

    return frozenset(assets)


def generate_threat_db(
    tickets: list[dict],
    output_path: str,
    provider: OfflineEnrichmentProvider,
) -> None:
    """Build known_malicious_ips.json from confirmed-threat tickets.

    Each entry aggregates all threat intelligence extracted from every ticket
    that references that IP, merging attack types, CVEs, country, ISP, and
    blocklist sources across multiple ticket mentions.
    """
    resolved_statuses = {"resolved", "closed"}

    # Exclude monitored assets — public IPs that are defended
    # infrastructure, not threat actors.
    monitored = _build_monitored_assets(tickets)
    if monitored:
        console.print(
            f"[dim]  Monitored assets excluded from threat DB:"
            f" {len(monitored)} IPs[/dim]"
        )

    # ip → aggregated threat record
    ip_records: dict[str, dict] = {}
    processed = 0

    console.print(f"[dim]  Threat DB: processing {len(tickets):,} tickets...[/dim]")
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        processed += 1
        if processed % _PROGRESS_INTERVAL == 0:
            _progress("Threat DB", processed, len(tickets))

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        if result.disposition != Disposition.TRUE_POSITIVE:
            continue
        # Require reputation <= 30 (REPUTATION_TP_THRESHOLD): excludes low-confidence
        # ET-only tickets with no admin note (reputation 42) from the threat DB.
        # Only IPs with clear malicious evidence (reputation 0-30) are included.
        if result.score > 30:
            continue

        # Collect all text for extraction.
        # activity_text: only fields that describe what was directly observed against
        # our network (alert rule name + analyst investigation notes).  Used for
        # attack_types to avoid pollution from enrichment API blobs that list an IP's
        # global reputation (e.g. AbuseIPDB reports listing every category the IP has
        # ever been flagged for, regardless of what it did here).
        # all_text: includes description/additional_information/admin notes where
        # enrichment data lives — used for country, ISP, blocklist extraction which
        # legitimately benefit from that context.
        admin_note_text = "\n".join(
            n["text"] for n in ticket.get("notes", []) if n.get("is_admin_note")
        )
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

        attack_types = _extract_attack_types(activity_text)
        blocklists = _extract_blocklists(all_text)
        country_code = _extract_country_code(all_text)
        isp = _extract_isp(all_text)
        usage_type = _extract_usage_type(all_text)
        asn = _extract_asn(all_text)
        ticket_id = ticket["id"]
        updated = ticket.get("updated_at") or ticket.get("last_updated") or ""
        created = ticket.get("created_at", "")

        # Use explicit source/destination labels to filter out victim IPs.
        #
        # When the ticket description uses structured fields (source.ip / dest.ip /
        # Destination IP: etc.), we know precisely which IPs are attackers (source)
        # and which are defended assets (destination).
        #
        # Strategy:
        #   - If source IPs are labelled → only add those; everything else is a
        #     destination/bystander.  This handles multi-IP tickets (SIP scans,
        #     VoIP attacks) where dozens of IPs co-appear with the sensor IP.
        #   - If no source labels → fall back to excluding explicit dest IPs only.
        #     Preserves backwards-compat for tickets without structured descriptions.
        source_ips, dest_ips = _get_ip_roles(ticket)

        for ip in ticket.get("ips", []):
            if not _is_public(ip):
                continue
            if ip in monitored:
                continue
            if ip in dest_ips:
                continue
            if source_ips and ip not in source_ips:
                continue

            role: str | None = "source" if ip in source_ips else None

            if ip not in ip_records:
                # Scalar metadata: prefer text-extracted values from the ticket;
                # fall back to MaxMind GeoLite2 (country via AbuseIPDB cache first,
                # then GeoLite2-City; ASN/ISP from GeoLite2-ASN).
                ip_records[ip] = {
                    "ip": ip,
                    "org": lookup_org(ip),
                    "first_seen": created,
                    "last_seen": updated,
                    "ticket_ids": [],
                    "ticket_count": 0,
                    "attack_types": [],
                    "blocklists": [],
                    "country": country_code or provider.get_country(ip),
                    "isp": isp or provider.get_isp(ip),
                    "asn": asn or provider.get_asn(ip),
                    "usage_type": usage_type or None,
                    "role": role,
                    "summaries": [],
                }

            rec = ip_records[ip]
            rec["ticket_ids"].append(ticket_id)
            rec["ticket_count"] = len(rec["ticket_ids"])

            # Merge sets
            rec["attack_types"] = sorted(set(rec["attack_types"]) | set(attack_types))
            rec["blocklists"] = sorted(set(rec["blocklists"]) | set(blocklists))

            # Take first non-None value for scalar fields (prefer earlier tickets).
            # Text-extracted values win over MaxMind; MaxMind fills gaps.
            if not rec["country"]:
                rec["country"] = country_code or provider.get_country(ip)
            if not rec["isp"]:
                rec["isp"] = isp or provider.get_isp(ip)
            if not rec["asn"]:
                rec["asn"] = asn or provider.get_asn(ip)
            if not rec["usage_type"] and usage_type:
                rec["usage_type"] = usage_type
            # Upgrade role: once confirmed as source, keep it.
            if role == "source" and rec["role"] != "source":
                rec["role"] = "source"

            # Track date range
            if created and (not rec["first_seen"] or created < rec["first_seen"]):
                rec["first_seen"] = created
            if updated and (not rec["last_seen"] or updated > rec["last_seen"]):
                rec["last_seen"] = updated

            # Keep up to 3 unique summaries
            summary = ticket.get("summary", "")
            if (
                summary
                and summary not in rec["summaries"]
                and len(rec["summaries"]) < 3
            ):
                rec["summaries"].append(summary)

    _progress("Threat DB done", processed, len(tickets))

    # Remove single-ticket entries with no independent corroboration.
    # An IP that appears in exactly one ticket, has no blocklist hit, and was
    # never labelled as the source/attacker is too weak to treat as confirmed
    # malicious — a single analyst note could be wrong, and blocklist absence
    # means no external feed independently flagged the IP.  These are dropped
    # intentionally and do NOT appear in any other registry: they came from
    # TRUE_POSITIVE tickets, so generate_undetermined_registry (which only
    # captures UNDETERMINED disposition) will not pick them up.
    thin_before = len(ip_records)
    ip_records = {
        ip: rec
        for ip, rec in ip_records.items()
        if rec["ticket_count"] > 1
        or rec.get("blocklists")
        or rec.get("role") == "source"
    }
    thin_dropped = thin_before - len(ip_records)
    if thin_dropped:
        console.print(
            f"[yellow]  Dropped {thin_dropped} thin-evidence entries "
            f"(single ticket, no blocklist, no confirmed source role)[/yellow]"
        )

    # Sort by ticket_count descending (most-seen IPs first)
    records = sorted(ip_records.values(), key=lambda r: -r["ticket_count"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(records, fh, indent=2)
    os.rename(tmp, output_path)

    # Summary stats
    total_ips = len(records)
    with_country = sum(1 for r in records if r["country"])
    with_isp = sum(1 for r in records if r["isp"])
    multi_ticket = sum(1 for r in records if r["ticket_count"] > 1)

    attack_dist = Counter(a for r in records for a in r["attack_types"])

    console.print(
        f"[green]Threat DB: {total_ips} malicious IPs → {output_path}[/green]"
    )
    console.print(
        f"[dim]  {with_country} with country  |  "
        f"{with_isp} with ISP  |  {multi_ticket} seen in 2+ tickets[/dim]"
    )
    console.print("[dim]  Attack type breakdown:[/dim]")
    for attack, count in attack_dist.most_common():
        console.print(f"[dim]    {count:4d}  {attack}[/dim]")
