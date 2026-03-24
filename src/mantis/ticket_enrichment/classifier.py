"""Layered ticket classification: enhanced rules (Layer 1) + ML inference (Layer 2).

Public API:
    classify(ticket, use_ml=True)  -> ClassificationResult
    classify_rules(ticket)         -> ClassificationResult  (Layer 1 only)
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .categories import ET_CATEGORY_MAP, Disposition, ThreatType, Actor

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

# Strong FP signals in admin notes (+3).
# Used both for the benign-override on ET-category tickets and for score accumulation.
_FP_NOTE_STRONG = {
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
    # Commonly-used phrases in dataset
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
    "noise",
    "background noise",
    "internet noise",
    # Missed FP verdicts found in analysis
    "not a threat",
    "not a risk",
    "no risk",
    "not successful",
    "was not successful",
    "returned 0 bytes",
    "did not get far",
    "no response",
    "unrelated to the actual alert",
    "safe to close",
    "okay to close",
    "not compromised",
    "not related",
    # External scanners: these are FP sources, not org infrastructure
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
    """Return True if every occurrence of keyword in text is preceded by a negation.

    Scans an 8-word window before each match.  Returns False (not negated) as soon
    as any affirmative occurrence is found, so the disqualifier still fires if the
    keyword appears *both* in a negated and an affirmative context.
    """
    kw_re = re.compile(r"\b" + re.escape(keyword) + r"\b", re.I)
    found_any = False
    for m in kw_re.finditer(text):
        found_any = True
        # Extract up to 60 characters before the match as the look-back window
        window_start = max(0, m.start() - 60)
        window = text[window_start : m.start()]
        if not _NEGATION_RE.search(window):
            return False  # affirmative occurrence — not negated
    # If we found the keyword but every occurrence was negated, return True.
    # If we never found it at all, return False (caller's `kw in text` already
    # confirmed presence, so this branch shouldn't be reached in practice).
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


def _score_admin_notes(notes: list[dict]) -> tuple[int, list[str]]:
    """Score admin notes for benign/malicious signals.

    Returns (reputation_delta, signals) where reputation_delta is a signed
    integer to be applied to a base reputation of 50. Positive values push
    toward 100 (benign), negative toward 0 (malicious).
    """
    admin_texts = [n["text"] for n in notes if n.get("is_admin_note")]
    if not admin_texts:
        return 0, []

    all_lower = " ".join(admin_texts).lower()
    delta = 0
    signals: list[str] = []

    for kw in _FP_NOTE_STRONG:
        if kw in all_lower:
            delta += 35  # 50 + 35 = 85
            signals.append(f"admin_note: '{kw}'")
            break  # one strong signal is enough

    for kw in _INFRA_NOTE:
        if kw in all_lower:
            delta += 15  # 50 + 15 = 65
            signals.append(f"infra: '{kw}'")
            break

    # Check enrichment data in admin notes
    enrichment = _parse_enrichment_data(" ".join(admin_texts))
    if enrichment.get("greynoise_classification") == "benign":
        delta += 25  # 50 + 25 = 75
        signals.append("greynoise: benign")
    elif enrichment.get("greynoise_classification") == "malicious":
        delta -= 22  # 50 - 22 = 28
        signals.append("greynoise: malicious")

    if enrichment.get("abuseipdb_confidence", 0) >= 80:
        delta -= 22  # 50 - 22 = 28
        signals.append(f"abuseipdb: {enrichment['abuseipdb_confidence']}% confidence")
    elif enrichment.get("abuseipdb_confidence", 100) <= 10:
        delta += 15  # 50 + 15 = 65
        signals.append(
            f"abuseipdb: {enrichment['abuseipdb_confidence']}% confidence (low)"
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


def classify_rules(ticket: dict) -> ClassificationResult:
    """Layer 1: Enhanced rule-based classification."""
    summary = ticket.get("summary", "")
    summary_lower = summary.lower()
    resolution = ticket.get("resolution", "").lower()
    description = (ticket.get("description", "") or "").lower()
    notes = ticket.get("notes", [])
    admin_note_texts = [n["text"] for n in notes if n.get("is_admin_note")]
    all_note_lower = " ".join(admin_note_texts).lower()

    # --- Government/authorized scanner (highest priority) ---
    # Build a wider search string that includes ALL notes (not just admin notes)
    # for this specific check — CISA admissions may appear in regular user notes.
    all_notes_text = " ".join(n["text"] for n in notes).lower()
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

    # --- Admin note FP override (must run before malicious keyword scan) ---
    # Admin notes explaining benign context frequently use words like "malicious",
    # "exploit", or "threat actor" in negative clauses ("not malicious", "not
    # triggered by a threat actor").  If the note contains any strong FP signal —
    # AND no unambiguous malicious keyword — we classify as FALSE_POSITIVE so those
    # negated keywords never fire the hard disqualifier below.
    # The unambiguous-keyword guard prevents peripheral FP phrases ("returned 0 bytes")
    # from overriding notes that also contain clear threat signals.
    if admin_note_texts and any(kw in all_note_lower for kw in _FP_NOTE_STRONG):
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
        benign_override = any(kw in all_note_lower for kw in _FP_NOTE_STRONG)
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
            base_rep = 42

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
    signals: list[str] = []

    # Admin note scoring (Layer 1b) — returns a signed delta from 50
    note_delta, note_signals = _score_admin_notes(notes)
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

    # Layer 1c: Enrichment data from description
    enrichment = _parse_enrichment_data(description + " " + all_note_lower)
    if (
        enrichment.get("abuseipdb_confidence", 0) >= 90
        and disposition == Disposition.UNDETERMINED
    ):
        reputation = 10
        disposition = Disposition.TRUE_POSITIVE
        threat_type = ThreatType.BLOCKLIST_HIT
        signals.append(f"abuseipdb_confidence: {enrichment['abuseipdb_confidence']}%")
    elif (
        enrichment.get("greynoise_classification") == "benign"
        and disposition == Disposition.UNDETERMINED
    ):
        reputation = max(0, min(100, reputation + 25))
        disposition = Disposition.FALSE_POSITIVE
        signals.append("greynoise_benign_in_description")

    return ClassificationResult(
        disposition, threat_type, None, reputation, "rule", signals
    )


# ---------------------------------------------------------------------------
# Layer 2: ML inference (lazy-loaded)
# ---------------------------------------------------------------------------

_cached_model = None  # Cached (vectorizer, clf, label_names) tuple


def invalidate_model_cache():
    """Clear the cached ML model (call after retraining)."""
    global _cached_model
    _cached_model = None


def _classify_ml(ticket: dict) -> ClassificationResult | None:
    """Layer 2: TF-IDF + LinearSVC prediction. Returns None if model unavailable."""
    global _cached_model

    try:
        from .trainer import load_model, build_feature_text
    except ImportError:
        return None

    if _cached_model is None:
        _cached_model = load_model()
    if _cached_model is None:
        return None
    model_data = _cached_model

    vectorizer, clf, label_names = model_data

    # Handle stale model: if labels aren't valid Disposition values, reject
    try:
        for label in label_names:
            Disposition(label)
    except ValueError:
        return None

    text = build_feature_text(ticket)
    X = vectorizer.transform([text])

    prediction = clf.predict(X)[0]
    # Get confidence from decision_function
    decision = clf.decision_function(X)
    if decision.ndim == 1:
        # Binary case
        confidence = abs(float(decision[0]))
        confidence = min(1.0, confidence / 2.0)
    else:
        # Multi-class: use margin between top-2 classes as confidence signal
        scores = decision[0]
        sorted_scores = sorted(scores, reverse=True)
        top_score = sorted_scores[0]
        margin = (
            sorted_scores[0] - sorted_scores[1]
            if len(sorted_scores) > 1
            else abs(top_score)
        )
        if top_score <= 0:
            confidence = 0.0
        else:
            confidence = min(1.0, (top_score * 0.5 + margin * 0.5) / 1.5)

    predicted_label = label_names[prediction]
    disposition = Disposition(predicted_label)

    # Map ML confidence (0-1) to 0-100 reputation.
    # For benign predictions: reputation = 70 + round(confidence * 30) → 70-100
    # Keeps ML results above REPUTATION_FP_THRESHOLD (70) when accepted.
    if disposition in (Disposition.FALSE_POSITIVE, Disposition.BENIGN_TRUE_POSITIVE):
        reputation = 70 + round(confidence * 30)
    else:
        # Malicious predictions are rejected by the gate in classify(), but map
        # to low reputation (0-30) for completeness.
        reputation = 30 - round(confidence * 30)
    reputation = max(0, min(100, reputation))

    return ClassificationResult(
        disposition,
        None,
        None,
        reputation,
        "ml",
        [f"svm_prediction: {predicted_label}"],
    )


# ---------------------------------------------------------------------------
# Combined pipeline
# ---------------------------------------------------------------------------


def classify(ticket: dict, use_ml: bool = True) -> ClassificationResult:
    """Classify a ticket using layered pipeline: rules first, then ML for ambiguous cases."""
    result = classify_rules(ticket)

    # If rules produced a definitive answer, use it
    if result.disposition != Disposition.UNDETERMINED:
        return result

    # Layer 2: ML for tickets rules couldn't classify.
    # Only accept ML predictions of false_positive or benign_true_positive —
    # NOT true_positive. Reason: training data is ~92% true_positive (skewed),
    # so the model defaults to TP for any ambiguous ticket. Rules already handle
    # TP well; ML adds value by catching FP/benign patterns that rules missed.
    if use_ml:
        ml_result = _classify_ml(ticket)
        if (
            ml_result is not None
            and ml_result.score >= REPUTATION_FP_THRESHOLD
            and ml_result.disposition != Disposition.TRUE_POSITIVE
        ):
            return ml_result

    return result
