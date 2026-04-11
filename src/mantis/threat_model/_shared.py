"""Shared constants, regex patterns, and extraction helpers for threat_model generators."""

import ipaddress
import re

from rich.console import Console

from src.mantis.ticket_enrichment import nlp as _nlp_module

console = Console()

# Print a progress line every N tickets processed in each generator.
_PROGRESS_INTERVAL = 250


def _progress(label: str, done: int, total: int) -> None:
    """Print a compact progress line."""
    console.print(f"[dim]  {label}: {done:,}/{total:,} tickets[/dim]")


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
