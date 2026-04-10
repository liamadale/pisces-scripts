"""Rule-based ticket classification (Layer 1).

Public API:
    classify(ticket)       -> ClassificationResult
    classify_rules(ticket) -> ClassificationResult
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .categories import ET_CATEGORY_MAP, Disposition, ThreatType, Actor
from .offline import OfflineEnrichment

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ClassificationResult:
    disposition: Disposition
    threat_type: ThreatType | None  # None for FP/undetermined with no signal
    actor: Actor | None  # None when actor unknown
    score: int  # 0-100 reputation: >=70 benign, <=30 malicious, 31-69 undetermined
    method: str  # "rule" or "ml"
    signals: list[str] = field(default_factory=list)


# Reputation thresholds
REPUTATION_FP_THRESHOLD = 70  # >= 70 → FALSE_POSITIVE or BENIGN_TRUE_POSITIVE
REPUTATION_TP_THRESHOLD = 30  # <= 30 → TRUE_POSITIVE
# 31-69 → UNDETERMINED


# ---------------------------------------------------------------------------
# Pre-processing: defang IOC notation
# ---------------------------------------------------------------------------

_DEFANG_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"hxxps://", re.I), "https://"),
    (re.compile(r"hxxp://", re.I), "http://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[at\]", re.I), "@"),
]


def _defang(text: str) -> str:
    """Restore defanged IOC notation to canonical form.

    Analysts routinely defang IPs and URLs in notes to prevent accidental
    clicking (e.g. ``93.174.93[.]12``, ``hxxp://evil.com``).  Applying this
    before any keyword or regex matching ensures those indicators are
    recognised by downstream checks.
    """
    for pattern, replacement in _DEFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Government / authorized scanner regex
# ---------------------------------------------------------------------------

_GOV_SCANNER_RE = re.compile(
    r"\b(cyhy|cyber hygiene|nccic|ncats|cisa\s+(scan|vuln|assess|survey|cyber)|"
    r"dhs\s+(scan|vuln|assess|cyber|ncats)|"
    r"authorized\s+(vulnerability\s+)?scan|"
    r"shadowserver\.org|scan-\w+\.shadowserver|"
    r"censys\.io|censys\s+(scan|research|survey)|"
    r"rapid7\s+(scan|research|labs)|"
    r"qualys\s+(scan|guard)|"
    r"binaryedge|"
    r"stretchoid|"
    r"nessus\s+scan|tenable\.io|tenable\s+scan|"
    r"netspi|"
    r"onyphe\.io|onyphe\s+(scan|research)|"
    r"leakix|l9explore|"
    r"internet\s+census|internet.wide\s+scan)\b",
    re.I,
)

# More specific scanner patterns for actor assignment
_GOV_SCANNER_ACTORS: list[tuple[Actor, re.Pattern]] = [
    (
        Actor.CISA_CYHY,
        re.compile(r"\b(cyhy|cyber hygiene|nccic|ncats|cisa|dhs)\b", re.I),
    ),
    (Actor.SHADOWSERVER, re.compile(r"\bshadowserver\b", re.I)),
    (Actor.CENSYS, re.compile(r"\bcensys\b", re.I)),
    (Actor.RAPID7, re.compile(r"\brapid7\b", re.I)),
    (Actor.QUALYS, re.compile(r"\bqualys\b", re.I)),
    (Actor.BINARYEDGE, re.compile(r"\bbinaryedge\b", re.I)),
    (Actor.STRETCHOID, re.compile(r"\bstretchoid\b", re.I)),
    (Actor.NESSUS, re.compile(r"\b(nessus|tenable)\b", re.I)),
    (Actor.NETSPI, re.compile(r"\bnetspi\b", re.I)),
    (Actor.ONYPHE, re.compile(r"\bonyphe\b", re.I)),
    (Actor.LEAKIX, re.compile(r"\b(leakix|l9explore)\b", re.I)),
]


# ---------------------------------------------------------------------------
# Layer 1a: ET category parser
# ---------------------------------------------------------------------------

# Build regex from ET_CATEGORY_MAP keys, longest first to match "ET CURRENT_EVENTS" before "ET C..."
_ET_PREFIXES_SORTED = sorted(ET_CATEGORY_MAP.keys(), key=len, reverse=True)
_ET_RE = re.compile(
    r"\b(" + "|".join(re.escape(p) for p in _ET_PREFIXES_SORTED) + r")\b",
    re.I,
)


def _parse_et_category(summary: str) -> tuple[ThreatType, str] | None:
    """Extract ET rule category from summary. Returns (threat_type, matched_prefix) or None."""
    m = _ET_RE.search(summary)
    if m:
        matched = m.group(0).upper()
        for prefix, threat_type in ET_CATEGORY_MAP.items():
            if matched == prefix.upper():
                return threat_type, prefix
    return None


# ET category confidence tiers — how reliable is the category alone as a TP signal?
#
# HIGH (-3): Explicit blocklist membership or confirmed malware/trojan families.
#   No admin note needed; being listed on Spamhaus DROP / ET CINS is itself confirmation.
# MEDIUM (-2): Active attack/scan patterns. Reliable, but worth admin corroboration.
# LOW (-1): Informational/policy categories. Frequently FP; require admin corroboration
#   to enter the threat DB (score -1 is below the -2 threshold).
_ET_HIGH_CONFIDENCE = {
    "ET DROP",
    "ET CINS",
    "ET COMPROMISED",
    "ET TROJAN",
    "ET MALWARE",
    "ET MOBILE_MALWARE",
    "ET PHISHING",
    "ET SPAM",
}
_ET_MEDIUM_CONFIDENCE = {
    "ET SCAN",
    "ET EXPLOIT",
    "ET ATTACK_RESPONSE",
    "ET WEB_SERVER",
    "ET WEB_CLIENT",
    "ET DDOS",
    "ET DOS",
    "ET CURRENT_EVENTS",
}
# All others (ET INFO, ET POLICY, ET HUNTING, ET TOR, ET P2P, ET DNS) → LOW (-1 no note)


# ---------------------------------------------------------------------------
# Layer 1b: Expanded keyword sets
# ---------------------------------------------------------------------------

# Explicit FP verdicts in admin notes — the analyst is deliberately declaring
# the ticket benign.  These trigger the admin_note_fp_override hard return and
# the ET-category benign override.  Only include phrases an analyst would use
# intentionally to render a verdict, NOT incidental descriptors.
_FP_NOTE_EXPLICIT = {
    "false positive",
    "fp",
    "benign",
    "legitimate",
    "normal behavior",
    "normal traffic",
    "not malicious",
    "no action required",
    "no further action",
    "authorized",
    "whitelist",
    "no indicators of compromise",
    "no ioc",
    "expected behavior",
    "nothing malicious",
    # Commonly-used verdict phrases in dataset
    "whitelisted",
    "expected traffic",
    "internal scan",
    "patch scan",
    "vulnerability assessment",
    "pen test",
    "penetration test",
    "security audit",
    "scheduled scan",
    "it department",
    "approved scan",
    "sanctioned",
    "non-malicious",
    "non-threat",
    "no threat",
    "cleared",
    "verified safe",
    "no concern",
    # Outcome-based verdicts
    "not a threat",
    "not a risk",
    "no risk",
    "not successful",
    "was not successful",
    "unrelated to the actual alert",
    "safe to close",
    "okay to close",
    "not compromised",
    "not related",
}

# Contextual descriptors that suggest benign activity but are NOT explicit verdicts.
# An analyst mentioning "noise" or "censys" is describing what they observed, not
# necessarily declaring the ticket a false positive.  These are soft signals only —
# they contribute a small positive score delta in accumulation but do NOT gate the
# admin_note_fp_override or ET-category benign override hard returns.
_FP_NOTE_CONTEXT = {
    "noise",
    "background noise",
    "internet noise",
    "returned 0 bytes",
    "did not get far",
    "no response",
    # Scanner tool mentions — descriptive, not a verdict
    "censys",
    "shodan",
    "masscan",
    "internet scanner",
    "known scanner",
}

# Summary-level FP signals (+2)
_FP_SUMMARY = {
    "false positive",
    "fp traffic",
    "fp:",
    "possible false positive",
    "likely false positive",
    "potential false positive",
    "benign",
    "all attempts blocked",
    "all blocked",
    "unsuccessful attempt",
    "no success",
}

# Known-good infrastructure in admin notes (+1)
_INFRA_NOTE = {
    "cdn",
    "content delivery",
    "google dns",
    "google public dns",
    "8.8.8.8",
    "cloudflare",
    "akamai",
    # New expanded keywords
    "load balancer",
    "proxy",
    "vpn",
    "firewall",
    "monitoring",
    "nagios",
    "zabbix",
    "solarwinds",
    "palo alto",
    "fortinet",
    "microsoft",
    "amazon",
    "aws",
    "azure",
    "gcp",
}

# Confirmed malicious signals in admin notes (disqualifier).
# IMPORTANT: these are substring checks (kw in text). Only include phrases or words
# that cannot plausibly be substrings of common non-malicious words.
# BAD: "rat" matches "corroboration", "configuration", "administrative"
# BAD: "shell" matches "nutshell", "eggshell"
# BAD: "worm" matches "bookworm"
# GOOD: "botnet", "ransomware", "c2 beacon", "lateral movement" (long/specific phrases)
#
# NOTE: "malicious", "exploit", "threat actor", "trojan" are intentionally absent —
# they live in _MALICIOUS_NOTE_AMBIGUOUS and are checked with a negation guard because
# admin notes explaining benign traffic frequently use them in negative clauses
# ("not malicious", "not triggered by a threat actor", "not scanning/exploitation").
_MALICIOUS_NOTE = {
    "recommend block",
    "recommend blocking",
    "recommend quarantine",
    "botnet",
    "ransomware",
    "phishing",
    "spam bot",
    "command and control",
    "c2 beacon",
    "data exfiltration",
    "quarantine",
    "blocked at perimeter",
    "block the ip",
    "block ip",
    "block subnet",
    "compromised",
    "infected",
    "backdoor",
    "rootkit",
    "dropper",
    "lateral movement",
    "privilege escalation",
}

# Regex-based malicious note patterns for words that need word boundaries
# to avoid substring false matches ("rat" → "corroboration", "shell" → "nutshell", etc.)
_MALICIOUS_NOTE_RE = re.compile(
    r"\b(rat|shell|worm|cryptominer|crypto\s*miner|reverse\s+shell|web\s*shell|"
    r"meterpreter|mimikatz|cobalt\s*strike|persistence\s+mechanism)\b",
    re.I,
)

# Keywords that commonly appear in negated contexts within admin notes explaining
# benign traffic (e.g. "not malicious", "not scanning/exploitation", "not triggered
# by a threat actor").  These are checked with a negation guard instead of a bare
# substring match.  Unambiguous phrases (recommend block, c2 beacon, etc.) stay in
# _MALICIOUS_NOTE and are checked without the guard.
_MALICIOUS_NOTE_AMBIGUOUS: frozenset[str] = frozenset(
    {"malicious", "exploit", "threat actor", "trojan"}
)

# Negation window: if any of these words appear within 8 words before the keyword
# match we treat the occurrence as negated and skip the disqualifier.
_NEGATION_RE = re.compile(
    r"\b(not|no|never|isn't|aren't|doesn't|don't|wasn't|weren't|"
    r"non|cannot|can't|nor|without|unlikely|unrelated)\b",
    re.I,
)


def _keyword_negated(text: str, keyword: str) -> bool:
    """Return True if every occurrence of keyword in text is negated.

    Uses spaCy dependency parsing when available for accurate
    sentence-scoped negation detection.  Falls back to the regex
    lookback window when spaCy is not installed.
    """
    from . import nlp as _nlp_module

    result = _nlp_module.is_negated(text, keyword)
    if result is not None:
        return result

    # Regex fallback — 60-char lookback window.
    kw_re = re.compile(r"\b" + re.escape(keyword) + r"\b", re.I)
    found_any = False
    for m in kw_re.finditer(text):
        found_any = True
        window_start = max(0, m.start() - 60)
        window = text[window_start : m.start()]
        if not _NEGATION_RE.search(window):
            return False
    return found_any


# Summary keywords indicating confirmed threat (disqualifier)
_MALICIOUS_SUMMARY = {
    "et cins",
    "known malicious",
    "botnet",
    "ransomware",
    "phishing",
    "exploit",
    "cve-",
    "threat intelligence",
    "malware",
    "c2",
    "command and control",
    "data exfiltration",
}

# Resolution values that are strong FP signals
_FP_RESOLUTIONS = {"not a bug": 3, "unable to duplicate": 2}


# ---------------------------------------------------------------------------
# Layer 1c: Description field parsing (enrichment data)
# ---------------------------------------------------------------------------

_ABUSEIPDB_CONFIDENCE_RE = re.compile(
    r"(?:confidence\s+(?:of\s+)?abuse|abuse\s+confidence)\s*[:\s]+\s*(\d+)\s*%",
    re.I,
)

_GREYNOISE_CLASS_RE = re.compile(
    r"(?:classification|greynoise)\s*[:\s]+\s*(benign|malicious|unknown)",
    re.I,
)

_ABUSEIPDB_REPORTS_RE = re.compile(
    r"(?:total\s+reports|number\s+of\s+reports|reports)\s*[:\s]+\s*(\d+)",
    re.I,
)


def _parse_enrichment_data(text: str) -> dict:
    """Parse structured enrichment data from ticket description/notes."""
    result: dict = {}

    m = _ABUSEIPDB_CONFIDENCE_RE.search(text)
    if m:
        result["abuseipdb_confidence"] = int(m.group(1))

    m = _GREYNOISE_CLASS_RE.search(text)
    if m:
        result["greynoise_classification"] = m.group(1).lower()

    m = _ABUSEIPDB_REPORTS_RE.search(text)
    if m:
        result["abuseipdb_reports"] = int(m.group(1))

    return result


# ---------------------------------------------------------------------------
# Layer 1b: Score admin notes (expanded)
# ---------------------------------------------------------------------------


def _score_admin_notes(
    notes: list[dict],
    structured_gn: str | None = None,
    structured_abuse: int | None = None,
) -> tuple[int, list[str]]:
    """Score admin notes for benign/malicious signals.

    Returns (reputation_delta, signals) where reputation_delta is a signed
    integer to be applied to a base reputation of 50. Positive values push
    toward 100 (benign), negative toward 0 (malicious).

    Args:
        notes: Raw ticket note dicts.
        structured_gn: GreyNoise classification from ``OfflineEnrichment``
            (structured path).  When set, text-based GreyNoise parsing is
            skipped to avoid double-counting.
        structured_abuse: AbuseIPDB confidence from ``OfflineEnrichment``
            (structured path).  When set, text-based AbuseIPDB parsing is
            skipped to avoid double-counting.
    """
    admin_texts = [n["text"] for n in notes if n.get("is_admin_note")]
    if not admin_texts:
        return 0, []

    all_lower = " ".join(admin_texts).lower()
    delta = 0
    signals: list[str] = []

    for kw in _FP_NOTE_EXPLICIT:
        if kw in all_lower:
            delta += 35  # 50 + 35 = 85
            signals.append(f"admin_note: '{kw}'")
            break  # one strong signal is enough

    if delta == 0:
        for kw in _FP_NOTE_CONTEXT:
            if kw in all_lower:
                delta += 10  # 50 + 10 = 60 → UNDETERMINED, not FP
                signals.append(f"admin_note_context: '{kw}'")
                break

    for kw in _INFRA_NOTE:
        if kw in all_lower:
            delta += 15  # 50 + 15 = 65
            signals.append(f"infra: '{kw}'")
            break

    # Check enrichment data in admin notes — skip if structured data is
    # already present to avoid double-counting the same signal.
    enrichment_text = _parse_enrichment_data(" ".join(admin_texts))
    if structured_gn is None:
        if enrichment_text.get("greynoise_classification") == "benign":
            delta += 25  # 50 + 25 = 75
            signals.append("greynoise: benign")
        elif enrichment_text.get("greynoise_classification") == "malicious":
            delta -= 22  # 50 - 22 = 28
            signals.append("greynoise: malicious")

    if structured_abuse is None:
        if enrichment_text.get("abuseipdb_confidence", 0) >= 80:
            delta -= 22  # 50 - 22 = 28
            signals.append(
                f"abuseipdb: {enrichment_text['abuseipdb_confidence']}% confidence"
            )
        elif enrichment_text.get("abuseipdb_confidence", 100) <= 10:
            delta += 15  # 50 + 15 = 65
            signals.append(
                f"abuseipdb: {enrichment_text['abuseipdb_confidence']}% confidence"
                " (low)"
            )

    return delta, signals


# ---------------------------------------------------------------------------
# Private IP helper
# ---------------------------------------------------------------------------

_PRIVATE_IP_RE = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3})\b"
)


def _has_private_ip(ticket: dict) -> bool:
    """Return True if the ticket is associated with an RFC1918 (private) IP."""
    if ticket.get("private_ips"):
        return True
    for ip in ticket.get("ips", []):
        try:
            if ipaddress.ip_address(ip).is_private:
                return True
        except ValueError:
            pass
    return False


# ---------------------------------------------------------------------------
# DNS resolver IP helper
# ---------------------------------------------------------------------------

_KNOWN_DNS_RESOLVER_IPS: frozenset[str] = frozenset(
    {
        # Google
        "8.8.8.8",
        "8.8.4.4",
        # Cloudflare
        "1.1.1.1",
        "1.0.0.1",
        # Quad9
        "9.9.9.9",
        "149.112.112.112",
        # OpenDNS / Cisco Umbrella
        "208.67.222.222",
        "208.67.220.220",
        "208.67.222.123",
        "208.67.220.123",
        # NextDNS / AdGuard
        "94.140.14.14",
        "94.140.15.15",
    }
)


def is_known_dns_resolver(ip: str) -> bool:
    """Return True if ip is a well-known public DNS resolver."""
    return ip in _KNOWN_DNS_RESOLVER_IPS


def _has_dns_resolver_ip(ticket: dict) -> bool:
    """Return True if any IP in the ticket is a known public DNS resolver."""
    return any(is_known_dns_resolver(ip) for ip in ticket.get("ips", []))


# ---------------------------------------------------------------------------
# Layer 1: Combined rule-based classifier
# ---------------------------------------------------------------------------


def classify_rules(
    ticket: dict,
    enrichment: OfflineEnrichment | None = None,
) -> ClassificationResult:
    """Layer 1: Enhanced rule-based classification.

    Args:
        ticket: Raw ticket dict from tickets_index.json.
        enrichment: Optional offline enrichment hints (blocklist hits, Shodan
            tags, ASN tier, local reputation prior, and optional paid API
            results) produced by ``OfflineEnrichmentProvider.enrich_ticket()``.
            When ``None`` the classifier falls back to the original text-only
            logic with no degradation — all offline enrichment signals are
            simply absent.
    """

    # --- Pre-processing: defang IOC notation ---
    # Apply before any text extraction so defanged indicators are recognised.
    def _field(key: str) -> str:
        return _defang(ticket.get(key, "") or "")

    summary = _field("summary")
    summary_lower = summary.lower()
    resolution = ticket.get("resolution", "").lower()
    description = _defang(ticket.get("description", "") or "").lower()
    notes = ticket.get("notes", [])
    admin_note_texts = [_defang(n["text"]) for n in notes if n.get("is_admin_note")]
    all_note_lower = " ".join(admin_note_texts).lower()

    # --- Government/authorized scanner (highest priority) ---
    # Build a wider search string that includes ALL notes (not just admin notes)
    # for this specific check — CISA admissions may appear in regular user notes.
    all_notes_text = " ".join(_defang(n["text"]) for n in notes).lower()
    scanner_search_text = summary_lower + " " + all_notes_text + " " + description
    if _GOV_SCANNER_RE.search(scanner_search_text):
        actor = Actor.OTHER
        for a, pat in _GOV_SCANNER_ACTORS:
            if pat.search(scanner_search_text):
                actor = a
                break
        return ClassificationResult(
            Disposition.FALSE_POSITIVE,
            ThreatType.VULNERABILITY_SCAN,
            actor,
            100,
            "rule",
            ["gov_scanner_regex"],
        )

    # --- Offline enrichment signals ---
    # Signals produced by zero-cost offline lookups (blocklists, Shodan
    # InternetDB, ASN reputation, local registry priors).  These run before
    # any text-mining so that structured facts take precedence over keyword
    # pattern matching.
    offline_signals: list[str] = []
    if enrichment is not None:
        # Local reputation prior from previous analyst verdicts.
        # All three variants are soft signals — they push the score but do not
        # short-circuit evaluation.  Strong current-ticket evidence (blocklist
        # hits, explicit admin malicious notes, unambiguous FP verdicts) takes
        # precedence via the gates that follow.
        if enrichment.local_prior in ("false_positive", "malicious", "conflicted"):
            offline_signals.append(f"local_prior: {enrichment.local_prior}")

        # Blocklist hits — treat like ET HIGH confidence (score 18).
        # A strong FP note can still override (checked below in admin FP gate).
        if enrichment.blocklist_hits:
            has_admin_fp = any(kw in all_note_lower for kw in _FP_NOTE_EXPLICIT)
            if not has_admin_fp:
                return ClassificationResult(
                    Disposition.TRUE_POSITIVE,
                    ThreatType.BLOCKLIST_HIT,
                    None,
                    18,
                    "rule",
                    [f"blocklist: {', '.join(enrichment.blocklist_hits)}"],
                )
            offline_signals.append(
                f"blocklist_hit_overridden_by_fp: {', '.join(enrichment.blocklist_hits)}"
            )

        # Bulletproof ASN — TP weight added to score accumulation below.
        if enrichment.asn_tier == "bulletproof":
            offline_signals.append("asn_tier: bulletproof")

    # --- Admin note FP override (must run before malicious keyword scan) ---
    # Admin notes explaining benign context frequently use words like "malicious",
    # "exploit", or "threat actor" in negative clauses ("not malicious", "not
    # triggered by a threat actor").  If the note contains any strong FP signal —
    # AND no unambiguous malicious keyword — we classify as FALSE_POSITIVE so those
    # negated keywords never fire the hard disqualifier below.
    # The unambiguous-keyword guard prevents peripheral FP phrases ("returned 0 bytes")
    # from overriding notes that also contain clear threat signals.
    if admin_note_texts and any(kw in all_note_lower for kw in _FP_NOTE_EXPLICIT):
        has_unambiguous_threat = any(kw in all_note_lower for kw in _MALICIOUS_NOTE)
        if not has_unambiguous_threat:
            return ClassificationResult(
                Disposition.FALSE_POSITIVE,
                None,
                None,
                85,
                "rule",
                ["admin_note_fp_override"],
            )

    # --- Hard disqualifiers: confirmed malicious ---
    # Unambiguous phrases are checked with a bare substring match.
    # Ambiguous keywords (malicious, exploit, threat actor, trojan) go through a
    # negation guard so occurrences like "not malicious" or "not scanning/exploitation"
    # do not trigger the disqualifier.
    for kw in _MALICIOUS_NOTE:
        if kw in all_note_lower:
            return ClassificationResult(
                Disposition.TRUE_POSITIVE,
                ThreatType.UNKNOWN,
                None,
                0,
                "rule",
                [f"malicious_note: '{kw}'"],
            )
    for kw in _MALICIOUS_NOTE_AMBIGUOUS:
        if kw in all_note_lower and not _keyword_negated(all_note_lower, kw):
            return ClassificationResult(
                Disposition.TRUE_POSITIVE,
                ThreatType.UNKNOWN,
                None,
                0,
                "rule",
                [f"malicious_note: '{kw}'"],
            )
    m = _MALICIOUS_NOTE_RE.search(all_note_lower)
    if m:
        return ClassificationResult(
            Disposition.TRUE_POSITIVE,
            ThreatType.UNKNOWN,
            None,
            0,
            "rule",
            [f"malicious_note_re: '{m.group(0)}'"],
        )
    for kw in _MALICIOUS_SUMMARY:
        if kw in summary_lower:
            # Admin corroboration raises confidence: 15 with note, 42 without.
            # Score 42 is above TP_THRESHOLD (30) so no-admin-note tickets are excluded
            # from the threat DB unless they have other strong signals.
            score = 15 if admin_note_texts else 42
            return ClassificationResult(
                Disposition.TRUE_POSITIVE,
                ThreatType.UNKNOWN,
                None,
                score,
                "rule",
                [
                    f"malicious_summary: '{kw}'"
                    + ("" if admin_note_texts else " (no admin note)"),
                ],
            )

    # --- Private IP: organizational infrastructure ---
    # Runs after malicious disqualifiers so compromised internal hosts still get TRUE_POSITIVE.
    if _has_private_ip(ticket):
        return ClassificationResult(
            Disposition.BENIGN_TRUE_POSITIVE,
            None,
            None,
            90,
            "rule",
            ["private_ip: rfc1918"],
        )

    # --- Known public DNS resolvers ---
    if _has_dns_resolver_ip(ticket):
        return ClassificationResult(
            Disposition.BENIGN_TRUE_POSITIVE,
            None,
            Actor.DNS_RESOLVER,
            100,
            "rule",
            ["dns_resolver_ip"],
        )

    # --- Layer 1a: ET category from summary ---
    et_result = _parse_et_category(summary)
    if et_result:
        threat_type, prefix = et_result

        # Check for admin benign override first (covers missed FP verdicts in notes).
        benign_override = any(kw in all_note_lower for kw in _FP_NOTE_EXPLICIT)
        if benign_override:
            return ClassificationResult(
                Disposition.FALSE_POSITIVE,
                None,
                None,
                85,
                "rule",
                [f"et_category: {prefix}", "admin_override: benign"],
            )

        # Reputation by ET confidence tier × admin note presence.
        # Lower reputation = stronger malicious signal.
        prefix_upper = prefix.upper()
        if prefix_upper in _ET_HIGH_CONFIDENCE:
            # Blocklist/malware family: reliable even without admin note
            base_rep = 18
        elif prefix_upper in _ET_MEDIUM_CONFIDENCE:
            base_rep = 28
        else:
            # ET INFO, ET POLICY, ET HUNTING, ET TOR, ET P2P, ET DNS — informational/policy
            # These fire on routine traffic frequently; require admin note to be credible.
            # base_rep 38 keeps them UNDETERMINED by default but allows an admin
            # malicious note (38 - 8 = 30) to push to TRUE_POSITIVE, and ensures
            # they contribute accumulated negative reputation rather than disappearing.
            base_rep = 38

        # Admin note (non-benign) lowers reputation by 8 (adds confidence)
        rep = (base_rep - 8) if admin_note_texts else base_rep

        return ClassificationResult(
            Disposition.TRUE_POSITIVE,
            threat_type,
            None,
            rep,
            "rule",
            [
                f"et_category: {prefix}"
                + ("" if admin_note_texts else " (no admin note)")
            ],
        )

    # --- Score accumulation for ambiguous tickets (base reputation = 50) ---
    reputation = 50
    disposition = Disposition.UNDETERMINED
    threat_type: ThreatType | None = None
    signals: list[str] = list(offline_signals)

    # Offline enrichment score adjustments (applied first, before text scoring).
    # Shodan scanner/honeypot tags are strong FP priors (+25).
    # Bulletproof ASN is a strong TP prior (-20).
    # GreyNoise / AbuseIPDB structured results from paid API cache.
    # IP role: source (attacker) pushes toward TP (-8); dest (victim) pushes
    # toward FP (+8) — explicit labelling raises or lowers classification
    # confidence independent of the ticket keywords.
    _structured_gn: str | None = None
    _structured_abuse: int | None = None
    if enrichment is not None:
        # Local reputation prior: historical verdicts nudge the baseline before
        # other signals are applied.  FP prior (+20) pushes toward benign;
        # malicious prior (-22) pushes toward threat.  Both are weaker than a
        # fresh explicit admin note (+35 / hard disqualifier) so current-ticket
        # evidence dominates.  FP prior alone reaches exactly 70 (the FP
        # threshold) — any malicious signal in the current ticket drops it back
        # into UNDETERMINED or TRUE_POSITIVE.
        if enrichment.local_prior == "false_positive":
            reputation = max(0, min(100, reputation + 20))
        elif enrichment.local_prior == "malicious":
            reputation = max(0, min(100, reputation - 22))

        if enrichment.asn_tier == "bulletproof":
            reputation = max(0, min(100, reputation - 20))
        # Structured GreyNoise / AbuseIPDB from enrichment cache
        if enrichment.greynoise_classification == "benign":
            reputation = max(0, min(100, reputation + 25))
            signals.append("greynoise_structured: benign")
            _structured_gn = enrichment.greynoise_classification
        elif enrichment.greynoise_classification == "malicious":
            reputation = max(0, min(100, reputation - 22))
            signals.append("greynoise_structured: malicious")
            _structured_gn = enrichment.greynoise_classification
        if enrichment.abuseipdb_confidence is not None:
            _structured_abuse = enrichment.abuseipdb_confidence
            if enrichment.abuseipdb_confidence >= 80:
                reputation = max(0, min(100, reputation - 22))
                signals.append(
                    f"abuseipdb_structured: {enrichment.abuseipdb_confidence}%"
                )
            elif enrichment.abuseipdb_confidence <= 10:
                reputation = max(0, min(100, reputation + 15))
                signals.append(
                    f"abuseipdb_structured: {enrichment.abuseipdb_confidence}% (low)"
                )
        # IP role: explicit source/dest labelling adjusts confidence.
        if enrichment.ip_role == "source":
            reputation = max(0, min(100, reputation - 8))
            signals.append("ip_role: source")
        elif enrichment.ip_role == "dest":
            reputation = max(0, min(100, reputation + 8))
            signals.append("ip_role: dest")
        # Country: surface in signals for traceability; no score adjustment
        # (country alone is not a reliable TP/FP signal without corroboration).
        if enrichment.country:
            signals.append(f"country: {enrichment.country}")

    # Admin note scoring (Layer 1b) — returns a signed delta from 50
    note_delta, note_signals = _score_admin_notes(
        notes, _structured_gn, _structured_abuse
    )
    reputation = max(0, min(100, reputation + note_delta))
    signals.extend(note_signals)
    if reputation >= REPUTATION_FP_THRESHOLD:
        disposition = Disposition.FALSE_POSITIVE
    elif reputation <= REPUTATION_TP_THRESHOLD:
        disposition = Disposition.TRUE_POSITIVE
        threat_type = ThreatType.UNKNOWN

    # Infrastructure signals from notes
    if disposition == Disposition.UNDETERMINED and any(
        kw in all_note_lower for kw in _INFRA_NOTE
    ):
        if reputation > 50:
            disposition = Disposition.BENIGN_TRUE_POSITIVE

    # Resolution field — "not a bug" (+25), "unable to duplicate" (+15)
    res_delta_map = {"not a bug": 25, "unable to duplicate": 15}
    res_delta = res_delta_map.get(resolution, 0)
    if res_delta:
        reputation = max(0, min(100, reputation + res_delta))
        signals.append(f"resolution: '{resolution}'")
        if disposition == Disposition.UNDETERMINED:
            if resolution == "not a bug":
                disposition = Disposition.FALSE_POSITIVE

    # Summary-level FP signal (+25)
    if any(kw in summary_lower for kw in _FP_SUMMARY):
        reputation = max(0, min(100, reputation + 25))
        signals.append("fp_summary_keyword")
        if disposition == Disposition.UNDETERMINED:
            disposition = Disposition.FALSE_POSITIVE

    # Layer 1c: Enrichment data from description (text-parsed fallback).
    # Skip each service's text-based parsing if a structured result from the
    # enrichment cache is already present to avoid double-counting.
    enrichment_data = _parse_enrichment_data(description + " " + all_note_lower)
    if _structured_abuse is None and (
        enrichment_data.get("abuseipdb_confidence", 0) >= 90
        and disposition == Disposition.UNDETERMINED
    ):
        reputation = 10
        disposition = Disposition.TRUE_POSITIVE
        threat_type = ThreatType.BLOCKLIST_HIT
        signals.append(
            f"abuseipdb_confidence: {enrichment_data['abuseipdb_confidence']}%"
        )
    elif _structured_gn is None and (
        enrichment_data.get("greynoise_classification") == "benign"
        and disposition == Disposition.UNDETERMINED
    ):
        reputation = max(0, min(100, reputation + 25))
        disposition = Disposition.FALSE_POSITIVE
        signals.append("greynoise_benign_in_description")

    return ClassificationResult(
        disposition, threat_type, None, reputation, "rule", signals
    )


def classify(
    ticket: dict,
    enrichment: OfflineEnrichment | None = None,
) -> ClassificationResult:
    """Classify a ticket using rule-based pipeline."""
    return classify_rules(ticket, enrichment)
