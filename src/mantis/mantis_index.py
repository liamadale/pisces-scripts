#!/usr/bin/env python3
"""
Mantis bulk indexer — fetches all issues from the MantisBT REST API and writes
a local tickets_index.json for fast offline searching.

Usage:
    python src/mantis/mantis_index.py
    python src/mantis/mantis_index.py --max-pages 3   # quick smoke test (~150 tickets)
    python src/mantis/mantis_index.py --output data/tickets/tickets_index.json
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import time

import requests
import urllib3
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.dns import setup_dns
from src.mantis.mantis_search import _normalize_issue
from src.mantis.ticket_enrichment import (
    classify, classify_rules, train_model, invalidate_model_cache,
    Disposition,
)

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def build_index(
    api_url: str,
    api_token: str,
    page_size: int = 50,
    max_pages: int = 0,
) -> list[dict]:
    """Paginate through the MantisBT REST API and normalize every issue."""
    headers = {"Authorization": api_token}
    all_tickets: list[dict] = []

    # First request to discover total count
    try:
        resp = requests.get(
            f"{api_url}/api/rest/issues",
            headers=headers,
            params={"page_size": page_size, "page": 1},
            timeout=30,
            verify=False,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        console.print(f"[red]Initial API request failed: {exc}[/red]")
        return []

    data = resp.json()
    issues = data.get("issues", [])

    if not issues:
        console.print("[yellow]API returned no issues on page 1 — nothing to index.[/yellow]")
        return []

    # total_count is present but None on this Mantis instance; paginate until empty
    total_known = data.get("total_count")  # may be None
    if total_known:
        total_pages_est = (total_known + page_size - 1) // page_size
        console.print(f"[dim]{total_known} total tickets reported, ~{total_pages_est} pages[/dim]")
    else:
        console.print("[dim]total_count not available — paginating until empty page[/dim]")

    # Process page 1 results
    for issue in issues:
        all_tickets.append(_normalize_issue(issue, api_url))

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        # Use known total pages if available, else indeterminate
        total_for_bar = total_pages_est if total_known else None
        if max_pages:
            total_for_bar = max_pages
            console.print(f"[dim]Capped at {max_pages} pages ({max_pages * page_size} tickets)[/dim]")

        task = progress.add_task("Fetching tickets...", total=total_for_bar)
        progress.advance(task)  # page 1 already done

        page = 2
        while True:
            if max_pages and page > max_pages:
                break

            time.sleep(0.1)
            retried = False
            while True:
                try:
                    resp = requests.get(
                        f"{api_url}/api/rest/issues",
                        headers=headers,
                        params={"page_size": page_size, "page": page},
                        timeout=30,
                        verify=False,
                    )
                    resp.raise_for_status()
                    break
                except requests.Timeout:
                    if not retried:
                        retried = True
                        console.print(f"[yellow]Timeout on page {page}, retrying...[/yellow]")
                        time.sleep(2)
                        continue
                    console.print(f"[red]Page {page} timed out twice — stopping.[/red]")
                    return all_tickets
                except requests.RequestException as exc:
                    console.print(f"[red]Page {page} failed: {exc}[/red]")
                    return all_tickets

            page_issues = resp.json().get("issues", [])
            if not page_issues:
                break

            for issue in page_issues:
                all_tickets.append(_normalize_issue(issue, api_url))

            progress.advance(task)

            # If we got fewer than a full page, we're done
            if len(page_issues) < page_size:
                break

            page += 1

    return all_tickets


def generate_fp_candidates(tickets: list[dict], fp_output: str, use_ml: bool = False) -> None:
    """Write scored FP candidate IPs from resolved/closed tickets.

    Only includes IPs from tickets with a positive FP score and no disqualifying
    malicious signals. Outputs a flat IP list and a categorized JSON detail file.
    """
    resolved_statuses = {"resolved", "closed"}

    # ip → {disposition, threat_type, actor, score, ticket_ids}
    ip_data: dict[str, dict] = {}
    disposition_counts: dict[str, int] = {}

    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        result = classify(ticket, use_ml=use_ml) if use_ml else classify_rules(ticket)
        disp_key = result.disposition.value
        disposition_counts[disp_key] = disposition_counts.get(disp_key, 0) + 1

        # Skip confirmed threats and zero-score undetermined
        if result.disposition == Disposition.TRUE_POSITIVE:
            continue
        if result.score <= 0:
            continue

        for ip in ticket["ips"]:
            if ip not in ip_data:
                ip_data[ip] = {
                    "disposition": disp_key,
                    "threat_type": result.threat_type.value if result.threat_type else None,
                    "actor": result.actor.value if result.actor else None,
                    "score": result.score,
                    "ticket_ids": [],
                }
            else:
                # Upgrade if this ticket is stronger evidence
                if result.score > ip_data[ip]["score"]:
                    ip_data[ip]["disposition"] = disp_key
                    ip_data[ip]["threat_type"] = result.threat_type.value if result.threat_type else None
                    ip_data[ip]["actor"] = result.actor.value if result.actor else None
                    ip_data[ip]["score"] = result.score
            ip_data[ip]["ticket_ids"].append(ticket["id"])

    os.makedirs(os.path.dirname(fp_output), exist_ok=True)

    # Flat IP list (sorted)
    with open(fp_output, "w") as fh:
        for ip in sorted(ip_data):
            fh.write(ip + "\n")

    # Detailed JSON alongside the flat list
    detail_path = fp_output.replace(".txt", "_detail.json")
    detail = [
        {
            "ip": ip,
            "disposition": d["disposition"],
            "threat_type": d["threat_type"],
            "actor": d["actor"],
            "score": d["score"],
            "ticket_ids": sorted(set(d["ticket_ids"])),
        }
        for ip, d in sorted(ip_data.items())
    ]
    with open(detail_path, "w") as fh:
        json.dump(detail, fh, indent=2)

    console.print(f"[green]FP candidates: {len(ip_data)} IPs → {fp_output}[/green]")
    console.print(f"[dim]  Detail: {detail_path}[/dim]")
    console.print("[dim]  Ticket disposition breakdown:[/dim]")
    for disp, count in sorted(disposition_counts.items(), key=lambda x: -x[1]):
        console.print(f"[dim]    {count:5d}  {disp}[/dim]")


# ---------------------------------------------------------------------------
# Threat extraction helpers
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r'CVE-\d{4}-\d+', re.I)

_ATTACK_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("exploit",       re.compile(r'\b(exploit|path traversal|sql inject|rce|remote code execution|'
                                 r'buffer overflow|heap spray|shellcode|log4j|log4shell|heartbleed|'
                                 r'struts|jboss|webshell)\b', re.I)),
    ("port_scan",     re.compile(r'\b(port scan|portscan|scanning|recon|reconnaissance|nmap|masscan|'
                                 r'zmap|network scan|host scan|sweep)\b', re.I)),
    ("botnet",        re.compile(r'\b(botnet|mozi|mirai|c2|command.and.control|c&c|beacon|'
                                 r'beaconing|zombie|payload delivery)\b', re.I)),
    ("spam_phishing", re.compile(r'\b(spam|phishing|spambot|spam bot|phish|smishing|vishing|'
                                 r'credential harvest|credential theft)\b', re.I)),
    ("brute_force",   re.compile(r'\b(brute.forc|credential stuff|password spray|auth.attempt|'
                                 r'login attempt|failed auth|failed login|dictionary attack)\b', re.I)),
    ("ddos",          re.compile(r'\b(ddos|d\.d\.o\.s|dos |syn flood|amplification flood|'
                                 r'udp flood|ntp amplif|reflection attack)\b', re.I)),
    ("data_exfil",    re.compile(r'\b(exfil|data exfil|exfiltration|data theft|data leak|'
                                 r'beaconing out|dns tunnel)\b', re.I)),
    ("malware",       re.compile(r'\b(malware|trojan|ransomware|dropper|loader|rat\b|'
                                 r'rootkit|keylogger|infostealer|spyware|worm)\b', re.I)),
    ("iot_attack",    re.compile(r'\b(iot|scada|ot |modbus|dnp3|industrial control|'
                                 r'building automation|camera|router exploit)\b', re.I)),
]

_BLOCKLIST_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("dshield",         re.compile(r'\bdshield\b', re.I)),
    ("spamhaus_drop",   re.compile(r'\bspamhaus\b|\bDROP list\b|\bDROP Listed\b', re.I)),
    ("et_cins",         re.compile(r'\bET CINS\b|\bCINS Score\b|\bcinsscore\b', re.I)),
    ("feodo",           re.compile(r'\bfeodo\b', re.I)),
    ("abuse_ch",        re.compile(r'\babuse\.ch\b|\bthreatfox\b|\bbazaar\b', re.I)),
    ("emerging_threats",re.compile(r'\bemerging threats\b|\bET (DROP|BLOCK|SCAN|EXPLOIT)\b', re.I)),
    ("alienvault_otx",  re.compile(r'\balienvault\b|\botx\b', re.I)),
    ("greynoise",       re.compile(r'\bgreynoise\b', re.I)),
    ("abuseipdb",       re.compile(r'\babuseipdb\b', re.I)),
]

# Country name/adjective → ISO 3166-1 alpha-2
_COUNTRY_MAP: dict[str, str] = {
    "russia": "RU", "russian": "RU",
    "china": "CN", "chinese": "CN",
    "iran": "IR", "iranian": "IR",
    "north korea": "KP", "north korean": "KP",
    "romania": "RO", "romanian": "RO",
    "brazil": "BR", "brazilian": "BR",
    "india": "IN", "indian": "IN",
    "ukraine": "UA", "ukrainian": "UA",
    "turkey": "TR", "turkish": "TR",
    "vietnam": "VN", "vietnamese": "VN",
    "latvia": "LV", "latvian": "LV",
    "netherlands": "NL", "dutch": "NL",
    "germany": "DE", "german": "DE",
    "france": "FR", "french": "FR",
    "bulgaria": "BG", "bulgarian": "BG",
    "moldova": "MD", "moldovan": "MD",
    "slovenia": "SI", "slovenian": "SI",
    "australia": "AU", "australian": "AU",
    "canada": "CA", "canadian": "CA",
    "japan": "JP", "japanese": "JP",
    "hong kong": "HK",
    "south korea": "KR", "korean": "KR",
    "united states": "US", "american": "US", "domestic": "US",
    "united kingdom": "GB", "british": "GB",
}
_COUNTRY_RE = re.compile(
    r'\b(' + '|'.join(re.escape(k) for k in sorted(_COUNTRY_MAP, key=len, reverse=True)) + r')\b',
    re.I,
)

# Structured AbuseIPDB-style fields embedded in notes
_ISP_RE      = re.compile(r'(?:^|\n)\s*ISP\s{2,}(.+)', re.M)
_USAGE_RE    = re.compile(r'(?:^|\n)\s*Usage Type\s{2,}(.+)', re.M)
_ASN_RE      = re.compile(r'\b(AS\d{3,7})\b')
# Country from structured block: "AU Australia" or emoji + name
_COUNTRY_STRUCT_RE = re.compile(
    r'(?:^|\n)\s*(?:Country|🇦-🇿{1,2})\s{2,}(\w[\w\s]{2,30})', re.M
)
# Emoji flag + country name pattern e.g. "🇸🇮 Slovenia"
_EMOJI_COUNTRY_RE = re.compile(
    r'[\U0001F1E0-\U0001F1FF]{2}\s+([A-Za-z][\w\s]{2,25})'
)
# "AU Australia" style (2-letter code then name)
_CODE_COUNTRY_RE = re.compile(r'\b([A-Z]{2})\s+([A-Z][a-z][\w\s]{2,20})\b')


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


def _extract_attack_types(text: str) -> list[str]:
    return [name for name, pat in _ATTACK_PATTERNS if pat.search(text)]


def _extract_cves(text: str) -> list[str]:
    return sorted({m.group(0).upper() for m in _CVE_RE.finditer(text)})


def _extract_blocklists(text: str) -> list[str]:
    return [name for name, pat in _BLOCKLIST_PATTERNS if pat.search(text)]


def _is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return False


def generate_threat_db(tickets: list[dict], output_path: str, use_ml: bool = False) -> None:
    """Build known_malicious_ips.json from confirmed-threat tickets.

    Each entry aggregates all threat intelligence extracted from every ticket
    that references that IP, merging attack types, CVEs, country, ISP, and
    blocklist sources across multiple ticket mentions.
    """
    resolved_statuses = {"resolved", "closed"}

    # ip → aggregated threat record
    ip_records: dict[str, dict] = {}

    for ticket in tickets:
        if ticket.get("status", "").lower() not in resolved_statuses:
            continue
        if not ticket.get("ips"):
            continue

        result = classify(ticket, use_ml=use_ml) if use_ml else classify_rules(ticket)
        if result.disposition != Disposition.TRUE_POSITIVE:
            continue
        # Require score ≤ -2: excludes low-confidence ET-only tickets with no admin note.
        # Score tiers: -5 (explicit admin malicious keyword), -3/-4 (high-conf ET + admin),
        #              -2 (medium-conf ET or summary keyword with admin note),
        #              -1 (ET-only or summary-keyword with no admin note → excluded).
        if result.score > -2:
            continue

        # Collect all text for extraction
        admin_note_text = "\n".join(
            n["text"] for n in ticket.get("notes", []) if n.get("is_admin_note")
        )
        all_text = "\n".join(filter(None, [
            ticket.get("summary", ""),
            ticket.get("description", ""),
            ticket.get("steps_to_reproduce", ""),
            ticket.get("additional_information", ""),
            admin_note_text,
        ]))

        attack_types  = _extract_attack_types(all_text)
        cves          = _extract_cves(all_text)
        blocklists    = _extract_blocklists(all_text)
        country_code  = _extract_country_code(all_text)
        isp           = _extract_isp(all_text)
        usage_type    = _extract_usage_type(all_text)
        asn           = _extract_asn(all_text)
        ticket_id     = ticket["id"]
        updated       = ticket.get("updated_at") or ticket.get("last_updated") or ""
        created       = ticket.get("created_at", "")

        for ip in ticket.get("ips", []):
            if not _is_public(ip):
                continue

            if ip not in ip_records:
                ip_records[ip] = {
                    "ip":           ip,
                    "first_seen":   created,
                    "last_seen":    updated,
                    "ticket_ids":   [],
                    "ticket_count": 0,
                    "attack_types": [],
                    "cves":         [],
                    "blocklists":   [],
                    "country":      None,
                    "isp":          None,
                    "asn":          None,
                    "usage_type":   None,
                    "summaries":    [],
                }

            rec = ip_records[ip]
            rec["ticket_ids"].append(ticket_id)
            rec["ticket_count"] = len(rec["ticket_ids"])

            # Merge sets
            rec["attack_types"] = sorted(set(rec["attack_types"]) | set(attack_types))
            rec["cves"]         = sorted(set(rec["cves"]) | set(cves))
            rec["blocklists"]   = sorted(set(rec["blocklists"]) | set(blocklists))

            # Take first non-None value for scalar fields (prefer earlier tickets)
            if not rec["country"]    and country_code: rec["country"]    = country_code
            if not rec["isp"]        and isp:          rec["isp"]        = isp
            if not rec["asn"]        and asn:          rec["asn"]        = asn
            if not rec["usage_type"] and usage_type:   rec["usage_type"] = usage_type

            # Track date range
            if created and (not rec["first_seen"] or created < rec["first_seen"]):
                rec["first_seen"] = created
            if updated and (not rec["last_seen"] or updated > rec["last_seen"]):
                rec["last_seen"] = updated

            # Keep up to 3 unique summaries
            summary = ticket.get("summary", "")
            if summary and summary not in rec["summaries"] and len(rec["summaries"]) < 3:
                rec["summaries"].append(summary)

    # Sort by ticket_count descending (most-seen IPs first)
    records = sorted(ip_records.values(), key=lambda r: -r["ticket_count"])

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    tmp = output_path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(records, fh, indent=2)
    os.rename(tmp, output_path)

    # Summary stats
    total_ips    = len(records)
    with_country = sum(1 for r in records if r["country"])
    with_cves    = sum(1 for r in records if r["cves"])
    with_isp     = sum(1 for r in records if r["isp"])
    multi_ticket = sum(1 for r in records if r["ticket_count"] > 1)

    from collections import Counter
    attack_dist = Counter(a for r in records for a in r["attack_types"])

    console.print(f"[green]Threat DB: {total_ips} malicious IPs → {output_path}[/green]")
    console.print(f"[dim]  {with_country} with country  |  {with_cves} with CVEs  |  "
                  f"{with_isp} with ISP  |  {multi_ticket} seen in 2+ tickets[/dim]")
    console.print("[dim]  Attack type breakdown:[/dim]")
    for attack, count in attack_dist.most_common():
        console.print(f"[dim]    {count:4d}  {attack}[/dim]")


def _print_classify_stats(tickets: list[dict], use_ml: bool = False) -> None:
    """Print detailed classification breakdown for all tickets."""
    from collections import Counter

    disposition_counts: Counter = Counter()
    threat_type_counts: Counter = Counter()
    actor_counts: Counter = Counter()
    method_counts: Counter = Counter()
    undetermined_with_notes = 0

    for ticket in tickets:
        result = classify(ticket, use_ml=use_ml) if use_ml else classify_rules(ticket)
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
    console.print(f"\n[bold]Classification breakdown ({total} tickets, ml={'on' if use_ml else 'off'}):[/bold]")

    console.print("\n[dim]  By disposition:[/dim]")
    for disp, count in disposition_counts.most_common():
        pct = count / total * 100
        console.print(f"[dim]    {count:5d} ({pct:5.1f}%)  {disp}[/dim]")

    console.print(f"\n[dim]  Undetermined with admin notes: {undetermined_with_notes}[/dim]")

    console.print("\n[dim]  Threat type breakdown (true_positive tickets):[/dim]")
    for tt, count in threat_type_counts.most_common():
        console.print(f"[dim]    {count:5d}  {tt}[/dim]")

    console.print("\n[dim]  Actor breakdown (benign_true_positive tickets):[/dim]")
    for actor, count in actor_counts.most_common():
        console.print(f"[dim]    {count:5d}  {actor}[/dim]")

    console.print(f"\n[dim]  By method: {dict(method_counts)}[/dim]")


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Mantis Bulk Indexer")
    parser.add_argument(
        "--output",
        default=os.path.join(_BASE, "data", "tickets", "tickets_index.json"),
        help="Output path for tickets_index.json",
    )
    parser.add_argument(
        "--fp-output",
        default=os.path.join(_BASE, "data", "tickets", "fp_ips.txt"),
        help="Output path for FP candidate IP list",
    )
    parser.add_argument(
        "--threat-output",
        default=os.path.join(_BASE, "data", "tickets", "known_malicious_ips.json"),
        help="Output path for known_malicious_ips.json threat database",
    )
    parser.add_argument("--page-size", type=int, default=50, help="Issues per API page")
    parser.add_argument(
        "--max-pages", type=int, default=0, help="Max pages to fetch (0 = all)"
    )
    parser.add_argument(
        "--from-index", action="store_true",
        help="Skip API fetch; reprocess the existing tickets_index.json in place",
    )
    parser.add_argument(
        "--retrain", action="store_true",
        help="Force retrain ML classifier from current index (requires scikit-learn)",
    )
    parser.add_argument(
        "--classify-stats", action="store_true",
        help="Print detailed classification breakdown after indexing",
    )
    parser.add_argument(
        "--use-ml", action="store_true",
        help="Use ML classifier (Layer 2) in addition to rules for FP/threat generation",
    )
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    if args.from_index:
        if not os.path.exists(args.output):
            console.print(f"[red]Index not found: {args.output}[/red]")
            sys.exit(1)
        console.print(f"[dim]Loading existing index from {args.output}...[/dim]")
        with open(args.output) as fh:
            tickets = json.load(fh)
        console.print(f"[dim]Loaded {len(tickets)} tickets.[/dim]")
    else:
        api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
        api_token = os.environ.get("MANTIS_API_TOKEN", "")

        if not api_url or not api_token:
            console.print("[red]MANTIS_API_URL and MANTIS_API_TOKEN are required.[/red]")
            sys.exit(1)

        tickets = build_index(
            api_url=api_url,
            api_token=api_token,
            page_size=args.page_size,
            max_pages=args.max_pages,
        )

        if not tickets:
            console.print("[red]No tickets fetched — aborting write.[/red]")
            sys.exit(1)

        # Atomic write
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        tmp_path = args.output + ".tmp"
        with open(tmp_path, "w") as fh:
            json.dump(tickets, fh, indent=2)
        os.rename(tmp_path, args.output)

    console.print(f"[green]Indexed {len(tickets)} tickets → {args.output}[/green]")

    # Retrain ML model if requested
    if args.retrain:
        console.print("[dim]Training ML classifier (Layer 2)...[/dim]")
        label_dist = train_model(tickets)
        if label_dist is None:
            console.print("[yellow]ML training skipped — scikit-learn not installed or insufficient data[/yellow]")
        else:
            invalidate_model_cache()
            console.print(f"[green]ML model trained on {sum(label_dist.values())} tickets[/green]")
            console.print("[dim]  Training label distribution:[/dim]")
            for label, count in sorted(label_dist.items(), key=lambda x: -x[1]):
                console.print(f"[dim]    {count:5d}  {label}[/dim]")

    # Classification stats
    if args.classify_stats:
        _print_classify_stats(tickets, use_ml=args.use_ml)

    generate_fp_candidates(tickets, args.fp_output, use_ml=args.use_ml)
    generate_threat_db(tickets, args.threat_output, use_ml=args.use_ml)


if __name__ == "__main__":
    main()
