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
import ipaddress
import json
import os
import re
import sys

from dotenv import load_dotenv
from rich.console import Console

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.mantis.ticket_enrichment import (
    Actor,
    Disposition,
    OfflineEnrichmentProvider,
    classify_rules,
    is_known_dns_resolver,
    nlp as _nlp_module,
)
from src.utils.ip_org import lookup_org

console = Console()

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Print a progress line every N tickets processed in each generator.
_PROGRESS_INTERVAL = 250


def _progress(
    label: str, done: int, total: int, provider: OfflineEnrichmentProvider
) -> None:
    """Print a compact progress + Shodan API call counter line."""
    s = provider.stats()
    console.print(
        f"[dim]  {label}: {done:,}/{total:,} tickets"
        f"  |  Shodan: {s['shodan_api_calls']} live / {s['shodan_cache_hits']} cached"
        f"[/dim]"
    )


# ---------------------------------------------------------------------------
# Threat extraction helpers
# ---------------------------------------------------------------------------

_ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    (
        "exploit",
        re.compile(
            r"\b(exploit|path traversal|sql inject|rce|remote code execution|"
            r"buffer overflow|heap spray|shellcode|log4j|log4shell|heartbleed|"
            r"struts|jboss|webshell)\b",
            re.I,
        ),
    ),
    (
        "port_scan",
        re.compile(
            r"\b(port scan|portscan|scanning|recon|reconnaissance|nmap|masscan|"
            r"zmap|network scan|host scan|sweep)\b",
            re.I,
        ),
    ),
    (
        "botnet",
        re.compile(
            r"\b(botnet|mozi|mirai|c2|command.and.control|c&c|beacon|"
            r"beaconing|zombie|payload delivery)\b",
            re.I,
        ),
    ),
    (
        "spam_phishing",
        re.compile(
            r"\b(spam|phishing|spambot|spam bot|phish|smishing|vishing|"
            r"credential harvest|credential theft)\b",
            re.I,
        ),
    ),
    (
        "brute_force",
        re.compile(
            r"\b(brute.forc|credential stuff|password spray|auth.attempt|"
            r"login attempt|failed auth|failed login|dictionary attack)\b",
            re.I,
        ),
    ),
    (
        "ddos",
        re.compile(
            r"\b(ddos|d\.d\.o\.s|dos |syn flood|amplification flood|"
            r"udp flood|ntp amplif|reflection attack)\b",
            re.I,
        ),
    ),
    (
        "data_exfil",
        re.compile(
            r"\b(exfil|data exfil|exfiltration|data theft|data leak|"
            r"beaconing out|dns tunnel)\b",
            re.I,
        ),
    ),
    (
        "malware",
        re.compile(
            r"\b(malware|trojan|ransomware|dropper|loader|rat\b|"
            r"rootkit|keylogger|infostealer|spyware|worm)\b",
            re.I,
        ),
    ),
    (
        "iot_attack",
        re.compile(
            r"\b(iot|scada|ot |modbus|dnp3|industrial control|"
            r"building automation|camera|router exploit)\b",
            re.I,
        ),
    ),
]

_BLOCKLIST_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dshield", re.compile(r"\bdshield\b", re.I)),
    ("spamhaus_drop", re.compile(r"\bspamhaus\b|\bDROP list\b|\bDROP Listed\b", re.I)),
    ("et_cins", re.compile(r"\bET CINS\b|\bCINS Score\b|\bcinsscore\b", re.I)),
    ("feodo", re.compile(r"\bfeodo\b", re.I)),
    ("abuse_ch", re.compile(r"\babuse\.ch\b|\bthreatfox\b|\bbazaar\b", re.I)),
    (
        "emerging_threats",
        re.compile(r"\bemerging threats\b|\bET (DROP|BLOCK|SCAN|EXPLOIT)\b", re.I),
    ),
    ("alienvault_otx", re.compile(r"\balienvault\b|\botx\b", re.I)),
    ("greynoise", re.compile(r"\bgreynoise\b", re.I)),
    ("abuseipdb", re.compile(r"\babuseipdb\b", re.I)),
]

# Country name/adjective → ISO 3166-1 alpha-2
_COUNTRY_MAP: dict[str, str] = {
    "russia": "RU",
    "russian": "RU",
    "china": "CN",
    "chinese": "CN",
    "iran": "IR",
    "iranian": "IR",
    "north korea": "KP",
    "north korean": "KP",
    "romania": "RO",
    "romanian": "RO",
    "brazil": "BR",
    "brazilian": "BR",
    "india": "IN",
    "indian": "IN",
    "ukraine": "UA",
    "ukrainian": "UA",
    "turkey": "TR",
    "turkish": "TR",
    "vietnam": "VN",
    "vietnamese": "VN",
    "latvia": "LV",
    "latvian": "LV",
    "netherlands": "NL",
    "dutch": "NL",
    "germany": "DE",
    "german": "DE",
    "france": "FR",
    "french": "FR",
    "bulgaria": "BG",
    "bulgarian": "BG",
    "moldova": "MD",
    "moldovan": "MD",
    "slovenia": "SI",
    "slovenian": "SI",
    "australia": "AU",
    "australian": "AU",
    "canada": "CA",
    "canadian": "CA",
    "japan": "JP",
    "japanese": "JP",
    "hong kong": "HK",
    "south korea": "KR",
    "korean": "KR",
    "united states": "US",
    "american": "US",
    "domestic": "US",
    "united kingdom": "GB",
    "british": "GB",
}
_COUNTRY_RE = re.compile(
    r"\b("
    + "|".join(re.escape(k) for k in sorted(_COUNTRY_MAP, key=len, reverse=True))
    + r")\b",
    re.I,
)

# Structured AbuseIPDB-style fields embedded in notes
_ISP_RE = re.compile(r"(?:^|\n)\s*ISP\s{2,}(.+)", re.M)
_USAGE_RE = re.compile(r"(?:^|\n)\s*Usage Type\s{2,}(.+)", re.M)
_ASN_RE = re.compile(r"\b(AS\d{3,7})\b")
# Country from structured block: "AU Australia" or emoji + name
_COUNTRY_STRUCT_RE = re.compile(
    r"(?:^|\n)\s*(?:Country|🇦-🇿{1,2})\s{2,}(\w[\w\s]{2,30})", re.M
)
# Emoji flag + country name pattern e.g. "🇸🇮 Slovenia"
_EMOJI_COUNTRY_RE = re.compile(r"[\U0001F1E0-\U0001F1FF]{2}\s+([A-Za-z][\w\s]{2,25})")
# "AU Australia" style (2-letter code then name)
_CODE_COUNTRY_RE = re.compile(r"\b([A-Z]{2})\s+([A-Z][a-z][\w\s]{2,20})\b")


def _extract_isp(text: str) -> str | None:
    m = _ISP_RE.search(text)
    return m.group(1).strip() if m else None


def _extract_usage_type(text: str) -> str | None:
    m = _USAGE_RE.search(text)
    return m.group(1).strip() if m else None


def _extract_asn(text: str) -> str | None:
    m = _ASN_RE.search(text)
    return m.group(1).upper() if m else None


def _extract_country_code(text: str) -> str | None:
    """Try to extract a 2-letter ISO country code from freeform text."""
    # 1. Emoji flag + country name  e.g. "🇸🇮 Slovenia"
    for m in _EMOJI_COUNTRY_RE.finditer(text):
        name = m.group(1).strip().lower()
        for key, code in _COUNTRY_MAP.items():
            if key in name:
                return code

    # 2. "AU Australia" style
    for m in _CODE_COUNTRY_RE.finditer(text):
        candidate_code = m.group(1)
        candidate_name = m.group(2).lower()
        for key, code in _COUNTRY_MAP.items():
            if key in candidate_name and code == candidate_code:
                return code

    # 3. Plain country name/adjective in text
    m = _COUNTRY_RE.search(text)
    if m:
        return _COUNTRY_MAP.get(m.group(0).lower())

    return None


# Extracts source/destination IPs from the ticket's description fields.
# Ticket descriptions use several formats depending on the template version and
# whether the data was copied from Kibana:
#   "Source IP: <ip>" / "source.ip: <ip>" / "src ip: <ip>"
#   "Destination IP: <ip>" / "destination.ip: <ip>" / "destination.address: <ip>"
#   "dest ip: <ip>" — abbreviated informal template
_SOURCE_IP_RE = re.compile(
    r"source[\s.]*(?:ip|address)\s*[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)
_DEST_IP_RE = re.compile(
    r"dest(?:ination)?[\s.]*(?:ip|address)\s*[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.I,
)

_IP_LABEL_FIELDS = ("description", "steps_to_reproduce", "additional_information")


def _label_text(ticket: dict) -> str:
    """Return concatenated description-style fields used for source/dest extraction."""
    return "\n".join(filter(None, [ticket.get(f, "") or "" for f in _IP_LABEL_FIELDS]))


def _extract_source_ips(ticket: dict) -> frozenset[str]:
    """Return IPs explicitly labelled as source/attacker in the ticket description."""
    return frozenset(m.group(1) for m in _SOURCE_IP_RE.finditer(_label_text(ticket)))


def _extract_dest_ips(ticket: dict) -> frozenset[str]:
    """Return IPs explicitly labelled as destination/victim in the ticket description."""
    return frozenset(m.group(1) for m in _DEST_IP_RE.finditer(_label_text(ticket)))


def _get_ip_roles(ticket: dict) -> tuple[frozenset[str], frozenset[str]]:
    """Return (source_ips, dest_ips) for *ticket*.

    Prefers the pre-computed ``ip_src`` / ``ip_dest`` fields written by the
    indexer (``mantis_search._classify_ip_roles``).  Falls back to the legacy
    regex + NLP derivation for index files that predate these fields.
    """
    if ticket.get("ip_src") is not None or ticket.get("ip_dest") is not None:
        return (
            frozenset(ticket.get("ip_src") or []),
            frozenset(ticket.get("ip_dest") or []),
        )
    # Legacy fallback: re-derive from raw text (old index files)
    source_ips = _extract_source_ips(ticket)
    dest_ips = _extract_dest_ips(ticket)
    if not source_ips and not dest_ips:
        ip_roles = _nlp_module.extract_ip_roles(_label_text(ticket))
        if ip_roles is not None:
            source_ips = frozenset(r.ip for r in ip_roles if r.role == "source")
            dest_ips = frozenset(r.ip for r in ip_roles if r.role == "dest")
    return source_ips, dest_ips


_PROTO_EXPLICIT_RE = re.compile(r"\b(tcp|udp)/(\d{1,5})\b", re.I)
_PROTO_KEYWORDS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(dns|domain lookup|domain query)\b", re.I), "udp/53"),
    (re.compile(r"\bhttps\b", re.I), "tcp/443"),
    (re.compile(r"\bhttp\b", re.I), "tcp/80"),
    (re.compile(r"\bssh\b", re.I), "tcp/22"),
    (re.compile(r"\brdp\b", re.I), "tcp/3389"),
    (re.compile(r"\bsmb\b", re.I), "tcp/445"),
    (re.compile(r"\bsmtp\b", re.I), "tcp/25"),
    (re.compile(r"\bntp\b", re.I), "udp/123"),
    (re.compile(r"\b(icmp|ping sweep)\b", re.I), "icmp"),
]


def _extract_protocols(text: str) -> list[str]:
    """Extract protocol/port combinations from freeform ticket text."""
    found: set[str] = set()
    for m in _PROTO_EXPLICIT_RE.finditer(text):
        found.add(f"{m.group(1).lower()}/{m.group(2)}")
    for pattern, proto in _PROTO_KEYWORDS:
        if pattern.search(text):
            found.add(proto)
    return sorted(found)


def _extract_attack_types(text: str) -> list[str]:
    return [name for name, pat in _ATTACK_PATTERNS if pat.search(text)]


def _extract_blocklists(text: str) -> list[str]:
    return [name for name, pat in _BLOCKLIST_PATTERNS if pat.search(text)]


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (
            addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# FP candidate generation
# ---------------------------------------------------------------------------


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
            _progress("FP", processed, len(tickets), provider)

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

        for ip in ticket["ips"]:
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

    provider.flush_shodan_cache()
    _progress("FP done", processed, len(tickets), provider)

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


# ---------------------------------------------------------------------------
# Monitored-asset detection
# ---------------------------------------------------------------------------

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
    from collections import defaultdict

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


# ---------------------------------------------------------------------------
# Threat DB generation
# ---------------------------------------------------------------------------


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
            _progress("Threat DB", processed, len(tickets), provider)

        result = classify_rules(ticket, provider.enrich_ticket(ticket))
        if result.disposition != Disposition.TRUE_POSITIVE:
            continue
        # Require reputation <= 30 (REPUTATION_TP_THRESHOLD): excludes low-confidence
        # ET-only tickets with no admin note (reputation 42) from the threat DB.
        # Only IPs with clear malicious evidence (reputation 0-30) are included.
        if result.score > 30:
            continue

        # Collect all text for extraction
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

        attack_types = _extract_attack_types(all_text)
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
                # Country: prefer text-extracted value; fall back to API cache.
                cached_country = provider.get_country(ip)
                ip_records[ip] = {
                    "ip": ip,
                    "org": lookup_org(ip),
                    "first_seen": created,
                    "last_seen": updated,
                    "ticket_ids": [],
                    "ticket_count": 0,
                    "attack_types": [],
                    "blocklists": [],
                    "country": country_code or cached_country,
                    "isp": isp or None,
                    "asn": asn or None,
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

            # Take first non-None value for scalar fields (prefer earlier tickets)
            if not rec["country"]:
                rec["country"] = country_code or provider.get_country(ip)
            if not rec["isp"] and isp:
                rec["isp"] = isp
            if not rec["asn"] and asn:
                rec["asn"] = asn
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

    provider.flush_shodan_cache()
    _progress("Threat DB done", processed, len(tickets), provider)

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

    from collections import Counter

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


# ---------------------------------------------------------------------------
# Infrastructure registry generation
# ---------------------------------------------------------------------------


def generate_infra_registry(
    tickets: list[dict],
    output_path: str,
    provider: OfflineEnrichmentProvider,
) -> None:
    """Build known_infra_ips.json from BENIGN_TRUE_POSITIVE tickets.

    Only IPs from tickets classified as BENIGN_TRUE_POSITIVE (authorized scanners,
    CDN, gov probes) are included. Each entry aggregates protocols observed and
    attack contexts (ticket summaries) across all tickets referencing that IP.
    """
    resolved_statuses = {"resolved", "closed"}
    ip_records: dict[str, dict] = {}
    processed = 0

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
            _progress("Infra", processed, len(tickets), provider)

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
        attack_types = _extract_attack_types(all_text)
        ticket_id = str(ticket["id"])
        created = ticket.get("created_at", "")
        updated = ticket.get("updated_at") or ticket.get("last_updated") or ""
        summary = ticket.get("summary", "")
        actor_val = result.actor.value if result.actor else None

        for ip in ticket.get("ips", []):
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
        all_text = "\n".join(
            filter(
                None,
                [ticket.get("summary", ""), ticket.get("description", "")],
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

    provider.flush_shodan_cache()
    _progress("Infra done", processed, len(tickets), provider)

    for rec in ip_records.values():
        rec["ticket_ids"] = sorted(set(rec["ticket_ids"]))

    records = sorted(ip_records.values(), key=lambda r: r["ip"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(records, fh, indent=2)
    os.rename(tmp, output_path)

    console.print(f"[green]Infra registry: {len(records)} IPs → {output_path}[/green]")


# ---------------------------------------------------------------------------
# DNS resolver registry generation
# ---------------------------------------------------------------------------


def generate_dns_resolver_registry(tickets: list[dict], output_path: str) -> None:
    """Build dns_resolver_ips.json from tickets mentioning known public DNS resolvers.

    Aggregates ticket IDs and summaries for each known resolver IP seen across
    all tickets, regardless of resolution status.
    """
    ip_records: dict[str, dict] = {}

    for ticket in tickets:
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
    with open(tmp, "w") as fh:
        json.dump(records, fh, indent=2)
    os.rename(tmp, output_path)

    console.print(
        f"[green]DNS resolver registry: {len(records)} IPs → {output_path}[/green]"
    )


# ---------------------------------------------------------------------------
# Undetermined registry generation
# ---------------------------------------------------------------------------


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

    console.print(
        f"[dim]  Undetermined registry: processing {len(tickets):,} tickets...[/dim]"
    )
    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        processed += 1
        if processed % _PROGRESS_INTERVAL == 0:
            _progress("Undetermined", processed, len(tickets), provider)

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

    provider.flush_shodan_cache()
    _progress("Undetermined done", processed, len(tickets), provider)

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
    with open(tmp, "w") as fh:
        json.dump(records, fh, indent=2)
    os.rename(tmp, output_path)

    console.print(
        f"[green]Undetermined registry: {len(records)} IPs → {output_path}[/green]"
    )


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
            _progress("classify-stats", i, len(tickets), provider)

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

    provider.flush_shodan_cache()
    _progress("classify-stats done", len(tickets), len(tickets), provider)

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
# Cross-registry conflict resolution
# ---------------------------------------------------------------------------


def _resolve_registry_conflicts(
    threat_path: str,
    fp_path: str,
    undetermined_path: str,
) -> None:
    """Reconcile IPs that appear in both malicious_ips and false_positive_ips.

    Applies the majority-vote rule from §8 of the pipeline architecture doc:
        fp_count >= 3 * mal_count  → keep in FP only  (conflict_resolved_fp)
        mal_count >= 3 * fp_count  → keep in malicious only (conflict_resolved_tp)
        otherwise                  → move to undetermined (registry_conflict)

    All three output files are rewritten atomically (write to .tmp, then rename).
    """
    if not (os.path.exists(threat_path) and os.path.exists(fp_path)):
        return

    with open(threat_path) as fh:
        malicious: list[dict] = json.load(fh)
    with open(fp_path) as fh:
        fp_list: list[dict] = json.load(fh)

    mal_by_ip = {r["ip"]: r for r in malicious}
    fp_by_ip = {r["ip"]: r for r in fp_list}

    conflicted_ips = set(mal_by_ip) & set(fp_by_ip)
    if not conflicted_ips:
        console.print("[dim]  Registry conflict check: no conflicts found.[/dim]")
        return

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

    # Merge conflict-moved IPs into undetermined (may already have entries).
    if moved_to_undetermined:
        existing_undetermined: list[dict] = []
        if os.path.exists(undetermined_path):
            with open(undetermined_path) as fh:
                existing_undetermined = json.load(fh)
        existing_by_ip = {r["ip"]: r for r in existing_undetermined}
        for rec in moved_to_undetermined:
            existing_by_ip[rec["ip"]] = rec
        undetermined_sorted = sorted(existing_by_ip.values(), key=lambda r: r["ip"])
        tmp = undetermined_path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(undetermined_sorted, fh, indent=2)
        os.rename(tmp, undetermined_path)

    # Rewrite malicious and FP registries without the resolved conflicts.
    new_malicious = sorted(mal_by_ip.values(), key=lambda r: -r.get("ticket_count", 0))
    tmp = threat_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(new_malicious, fh, indent=2)
    os.rename(tmp, threat_path)

    new_fp = sorted(fp_by_ip.values(), key=lambda r: r["ip"])
    tmp = fp_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(new_fp, fh, indent=2)
    os.rename(tmp, fp_path)

    console.print(
        f"[yellow]Registry conflicts resolved: {len(conflicted_ips)} IPs[/yellow]"
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


# ---------------------------------------------------------------------------
# API enrichment pass (--enrich flag)
# ---------------------------------------------------------------------------


def _enrich_undetermined_ips(
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
        console.print(
            "[dim]  No undetermined registry found — skipping API enrichment.[/dim]"
        )
        return

    with open(undetermined_path) as fh:
        undetermined: list[dict] = json.load(fh)

    # Collect unique public IPs that need enrichment
    ips_to_enrich: list[str] = []
    seen: set[str] = set()
    for rec in undetermined:
        ip = rec.get("ip", "")
        if not ip or ip in seen:
            continue
        seen.add(ip)
        # Skip private / loopback
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_reserved:
                continue
        except ValueError:
            continue
        # Skip if already cached
        if provider.has_fresh_api_cache(ip):
            continue
        ips_to_enrich.append(ip)

    if not ips_to_enrich:
        console.print(
            "[dim]  All undetermined IPs already have fresh cache entries.[/dim]"
        )
        return

    console.print(
        f"[cyan]  Enriching {len(ips_to_enrich)} undetermined IPs via paid APIs...[/cyan]"
    )

    # Import here to avoid circular dependency and ensure .env is loaded
    from src.enricher import greynoise as _gn  # noqa: PLC0415
    from src.enricher import abuseipdb as _ab  # noqa: PLC0415

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

    console.print(
        f"[green]  API enrichment complete ({len(ips_to_enrich)} IPs).[/green]"
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
    with open(args.input) as fh:
        tickets = json.load(fh)
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
    generate_infra_registry(tickets, args.infra_output, provider)
    generate_dns_resolver_registry(tickets, args.dns_output)
    generate_undetermined_registry(tickets, args.undetermined_output, provider)

    if args.enrich:
        console.print("\n[bold cyan]API enrichment pass (--enrich)[/bold cyan]")
        _enrich_undetermined_ips(args.undetermined_output, provider)
        console.print(
            "[dim]Re-running registry generators with enriched signals...[/dim]"
        )
        generate_fp_candidates(tickets, args.fp_output, provider)
        generate_threat_db(tickets, args.threat_output, provider)
        generate_infra_registry(tickets, args.infra_output, provider)
        generate_undetermined_registry(tickets, args.undetermined_output, provider)

    _resolve_registry_conflicts(
        args.threat_output, args.fp_output, args.undetermined_output
    )


if __name__ == "__main__":
    main()
