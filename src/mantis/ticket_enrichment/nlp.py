"""spaCy NLP helpers for ticket classification.

Provides dependency-aware negation detection, IP role extraction,
and entity extraction.  Falls back gracefully when spaCy or the
``en_core_web_sm`` model is not installed.

Install::

    uv add --optional nlp spacy
    uv run python -m spacy download en_core_web_sm
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Lazy model loading
# ---------------------------------------------------------------------------

_nlp = None  # populated by _load() on first use
_load_attempted = False


def _load() -> None:
    """Try to load the spaCy model once."""
    global _nlp, _load_attempted
    if _load_attempted:
        return
    _load_attempted = True
    try:
        import spacy

        _nlp = spacy.load("en_core_web_sm")
    except (ImportError, OSError):
        pass


def is_available() -> bool:
    """Return True if spaCy and en_core_web_sm are loaded."""
    _load()
    return _nlp is not None


# ---------------------------------------------------------------------------
# Negation detection
# ---------------------------------------------------------------------------

# Verbs whose meaning implies negation of their complement clause.
_SEMANTIC_NEGATORS: frozenset[str] = frozenset(
    {
        "fail",
        "fails",
        "failed",
        "lack",
        "lacks",
        "lacked",
        "lacking",
        "unable",
        "deny",
        "denies",
        "denied",
        "refuse",
        "refuses",
        "refused",
        "prevent",
        "prevents",
        "prevented",
        "doubt",
        "doubts",
        "doubted",
    }
)


# Tokens that negate when they appear as a sibling modifier
# (e.g. "non malicious" where "non" is nmod of the same head).
_NEG_PREFIXES: frozenset[str] = frozenset(
    {"non", "no", "not", "never", "without", "unlikely"}
)


def _token_has_neg_child(token) -> bool:  # type: ignore[no-untyped-def]
    """Return True if *token* has a direct ``neg`` dependent."""
    return any(c.dep_ == "neg" for c in token.children)


def _has_neg_sibling(token) -> bool:  # type: ignore[no-untyped-def]
    """Return True if a sibling under the same head is a negation word.

    Catches patterns like "non malicious traffic" where spaCy parses
    "non" as ``nmod`` of "traffic" (sibling of "malicious") rather
    than a ``neg`` dependent.
    """
    head = token.head
    for child in head.children:
        if child.i == token.i:
            continue
        if child.text.lower() in _NEG_PREFIXES:
            # Must be adjacent or very close to the keyword.
            if abs(child.i - token.i) <= 2:
                return True
    return False


def _is_under_negation(token) -> bool:  # type: ignore[no-untyped-def]
    """Walk the head chain from *token* and check for negation.

    Checks:
    1. Direct ``neg`` child on the token itself or any ancestor
       up to the clause root.
    2. Sibling negation prefixes (non, no, ...) under the same
       head as the keyword.
    3. Semantic negator verbs (fail, lack, ...) as an ancestor.
    """
    # Check the keyword's own children for negation prefixes
    # (handles "thankfully non malicious" where "non" is advmod
    # of "malicious").
    for child in token.children:
        if child.text.lower() in _NEG_PREFIXES:
            return True

    # Check siblings under the same head (handles "non malicious
    # traffic" where both are modifiers of "traffic").
    if _has_neg_sibling(token):
        return True

    cur = token
    visited: set[int] = set()
    while cur.i not in visited:
        visited.add(cur.i)
        if _token_has_neg_child(cur):
            return True
        if cur.lemma_ in _SEMANTIC_NEGATORS or (cur.text.lower() in _SEMANTIC_NEGATORS):
            return True
        if cur.head == cur:
            break
        cur = cur.head
    return False


def is_negated(text: str, keyword: str) -> bool | None:
    """Check if *keyword* is negated in *text* using dependency parsing.

    Returns ``True`` if **all** occurrences are negated, ``False``
    if any affirmative occurrence exists, or ``None`` if spaCy is
    unavailable (caller should fall back to regex).
    """
    _load()
    if _nlp is None:
        return None

    doc = _nlp(text)
    kw_lower = keyword.lower()
    kw_re = re.compile(r"\b" + re.escape(kw_lower) + r"\b", re.I)

    found_any = False
    for sent in doc.sents:
        sent_text = sent.text.lower()
        if not kw_re.search(sent_text):
            continue

        # Find tokens in this sentence that match the keyword.
        for token in sent:
            if token.text.lower() == kw_lower or (token.lemma_.lower() == kw_lower):
                found_any = True
                if not _is_under_negation(token):
                    return False  # affirmative occurrence

    if not found_any:
        return None  # keyword not found as token; let regex handle
    return True


# ---------------------------------------------------------------------------
# IP role extraction
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# Prepositions/verbs that indicate directionality.
_SOURCE_PREPS: frozenset[str] = frozenset({"from", "by"})
_DEST_PREPS: frozenset[str] = frozenset(
    {"to", "toward", "towards", "targeting", "against"}
)
_ATTACK_VERBS: frozenset[str] = frozenset(
    {
        "attack",
        "scan",
        "probe",
        "exploit",
        "compromise",
        "infect",
        "target",
        "flood",
        "brute",
        "send",
        "sent",
        "originate",
        "originated",
    }
)

# Token text that labels an adjacent IP as source or dest.
_SOURCE_LABELS: frozenset[str] = frozenset(
    {"source", "src", "attacker", "sender", "origin"}
)
_DEST_LABELS: frozenset[str] = frozenset(
    {"destination", "dest", "target", "victim", "receiver"}
)


@dataclass
class IpRole:
    """An IP address with its determined role in the text."""

    ip: str
    role: str  # "source" | "dest" | "unknown"


def _find_governing_prep(token) -> str | None:  # type: ignore[no-untyped-def]
    """Walk up from *token* to find a governing preposition."""
    cur = token
    visited: set[int] = set()
    while cur.i not in visited:
        visited.add(cur.i)
        if cur.dep_ == "pobj" and cur.head.pos_ == "ADP":
            return cur.head.text.lower()
        if cur.head == cur:
            break
        cur = cur.head
    return None


def _role_from_verb(token) -> str | None:  # type: ignore[no-untyped-def]
    """Determine role from the IP's relation to an attack verb.

    Handles both active and passive voice:
    - Active: "X scanned Y" → X=source, Y=dest
    - Passive: "Y was targeted by X" → Y=dest, X=source
    """
    cur = token
    visited: set[int] = set()
    while cur.i not in visited:
        visited.add(cur.i)
        head = cur.head
        if head.lemma_ in _ATTACK_VERBS:
            # Passive subject (nsubjpass) is the victim/dest.
            if cur.dep_ == "nsubjpass":
                return "dest"
            if cur.dep_ == "nsubj":
                return "source"
            if cur.dep_ == "agent":
                return "source"
            if cur.dep_ in ("dobj", "attr"):
                return "dest"
        if head == cur:
            break
        cur = head
    return None


def _role_from_label(token) -> str | None:  # type: ignore[no-untyped-def]
    """Check if *token* has a compound/appos child that labels it."""
    for child in token.children:
        if child.dep_ in ("compound", "appos", "amod"):
            low = child.text.lower()
            if low in _SOURCE_LABELS:
                return "source"
            if low in _DEST_LABELS:
                return "dest"
    # Also check if the token itself is a child whose head is
    # labeled (e.g. "source IP 78.153.140.0" where source is
    # compound of 78.153.140.0).
    if token.dep_ in ("compound", "appos", "nummod"):
        for sibling in token.head.children:
            if sibling.i == token.i:
                continue
            if sibling.dep_ in ("compound", "appos", "amod"):
                low = sibling.text.lower()
                if low in _SOURCE_LABELS:
                    return "source"
                if low in _DEST_LABELS:
                    return "dest"
    return None


def extract_ip_roles(text: str) -> list[IpRole] | None:
    """Extract IP addresses and their roles from freeform text.

    Returns a list of :class:`IpRole` or ``None`` if spaCy is
    unavailable.
    """
    _load()
    if _nlp is None:
        return None

    matches = list(_IPV4_RE.finditer(text))
    if not matches:
        return []

    doc = _nlp(text)

    # Map char offset → token index for fast lookup.
    offset_to_token: dict[int, int] = {}
    for token in doc:
        offset_to_token[token.idx] = token.i

    results: list[IpRole] = []
    for m in matches:
        ip_str = m.group(1)
        start = m.start()

        # Find the token at this character offset.
        tok_idx = offset_to_token.get(start)
        if tok_idx is None:
            # IP might span multiple tokens; find closest.
            for offset in range(start, start + len(ip_str)):
                tok_idx = offset_to_token.get(offset)
                if tok_idx is not None:
                    break
        if tok_idx is None:
            results.append(IpRole(ip=ip_str, role="unknown"))
            continue

        token = doc[tok_idx]

        # Strategy 0: adjacent compound label ("source IP X",
        # "destination 10.10.3.39").
        label_role = _role_from_label(token)
        if label_role is not None:
            results.append(IpRole(ip=ip_str, role=label_role))
            continue

        # Strategy 1: governing preposition
        prep = _find_governing_prep(token)
        if prep in _SOURCE_PREPS:
            results.append(IpRole(ip=ip_str, role="source"))
            continue
        if prep in _DEST_PREPS:
            results.append(IpRole(ip=ip_str, role="dest"))
            continue

        # Strategy 2: verb relation
        verb_role = _role_from_verb(token)
        if verb_role is not None:
            results.append(IpRole(ip=ip_str, role=verb_role))
            continue

        results.append(IpRole(ip=ip_str, role="unknown"))

    return results


# ---------------------------------------------------------------------------
# Entity extraction
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)

# spaCy NER labels that tend to produce noise on security text.
_NER_NOISE: frozenset[str] = frozenset(
    {"ET", "CINS", "DROP", "SCAN", "INFO", "TOR", "P2P", "DNS"}
)


def extract_entities(
    text: str,
) -> dict[str, list[str]] | None:
    """Extract structured entities from ticket text.

    Returns ``{"orgs": [...], "countries": [...], "cves": [...]}``
    or ``None`` if spaCy is unavailable.
    """
    _load()
    if _nlp is None:
        return None

    doc = _nlp(text)

    orgs: list[str] = []
    countries: list[str] = []
    for ent in doc.ents:
        if ent.label_ == "ORG":
            name = ent.text.strip()
            if (
                name.upper() not in _NER_NOISE
                and len(name) > 1
                and not _CVE_RE.search(name)
            ):
                orgs.append(name)
        elif ent.label_ == "GPE":
            countries.append(ent.text.strip())

    cves = _CVE_RE.findall(text)

    return {
        "orgs": sorted(set(orgs)),
        "countries": sorted(set(countries)),
        "cves": sorted(set(c.upper() for c in cves)),
    }
