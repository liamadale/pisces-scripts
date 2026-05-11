"""Startup data loading and in-memory indices for the Threat Modeling app."""

import json
import os
from collections import defaultdict
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
# apps/threat_model/ → go 2 levels up to reach repo root
_REPO = os.path.dirname(os.path.dirname(_HERE))
DATA_DIR = os.path.join(_REPO, "data", "tickets")


def _load(name: str) -> list:
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _load_optional(name: str) -> list:
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Well-known public DNS resolver metadata — name/provider for display
# ---------------------------------------------------------------------------
_KNOWN_DNS_RESOLVERS: dict[str, dict] = {
    "8.8.8.8": {"name": "Google Public DNS", "provider": "Google"},
    "8.8.4.4": {"name": "Google Public DNS", "provider": "Google"},
    "1.1.1.1": {"name": "Cloudflare DNS", "provider": "Cloudflare"},
    "1.0.0.1": {"name": "Cloudflare DNS", "provider": "Cloudflare"},
    "9.9.9.9": {"name": "Quad9 DNS", "provider": "Quad9"},
    "149.112.112.112": {"name": "Quad9 DNS", "provider": "Quad9"},
    "208.67.222.222": {"name": "OpenDNS", "provider": "Cisco Umbrella"},
    "208.67.220.220": {"name": "OpenDNS", "provider": "Cisco Umbrella"},
    "208.67.222.123": {"name": "OpenDNS FamilyShield", "provider": "Cisco Umbrella"},
    "208.67.220.123": {"name": "OpenDNS FamilyShield", "provider": "Cisco Umbrella"},
    "94.140.14.14": {"name": "AdGuard DNS", "provider": "AdGuard"},
    "94.140.15.15": {"name": "AdGuard DNS", "provider": "AdGuard"},
}
_DNS_RESOLVER_IPS: frozenset[str] = frozenset(_KNOWN_DNS_RESOLVERS)

# ---------------------------------------------------------------------------
# Raw data
# ---------------------------------------------------------------------------
_raw_tickets = _load("indexed/tickets_index.json")
_raw_malicious = [
    r for r in _load("enriched/malicious_ips.json") if r["ip"] not in _DNS_RESOLVER_IPS
]
_raw_fp = [r for r in _load("enriched/false_positive_ips.json") if r["ip"] not in _DNS_RESOLVER_IPS]
_raw_infra = _load_optional("enriched/known_infra_ips.json")
_raw_dns_resolvers = _load_optional("enriched/dns_resolver_ips.json")
_raw_undetermined = _load_optional("enriched/undetermined_ips.json")
_raw_profiles = _load_optional("enriched/private_ip_profiles.json")

# True when the pipeline has been run and data files exist.
DATA_AVAILABLE: bool = bool(_raw_tickets or _raw_malicious or _raw_fp)

# ---------------------------------------------------------------------------
# Indices
# ---------------------------------------------------------------------------
TICKETS_BY_ID = {str(t["id"]): t for t in _raw_tickets}

TICKETS_BY_IP: dict[str, list[str]] = defaultdict(list)
for _t in _raw_tickets:
    for _ip in _t.get("ips") or []:
        TICKETS_BY_IP[_ip].append(str(_t["id"]))

MALICIOUS_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_malicious}
FP_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_fp}
INFRA_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_infra}
UNDETERMINED_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_undetermined}
PROFILES_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_profiles}

# Build DNS resolver index from enriched file; fall back to known-list entries
# for any resolver not yet in the enriched file.
DNS_RESOLVER_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_dns_resolvers}
for _ip, _meta in _KNOWN_DNS_RESOLVERS.items():
    if _ip not in DNS_RESOLVER_BY_IP:
        DNS_RESOLVER_BY_IP[_ip] = {"ip": _ip, "ticket_ids": [], "summaries": []}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return ""
    return "".join(chr(ord(c) + 127397) for c in code.upper())


def fmt_attack(at: str) -> str:
    return at.replace("_", " ").title()


def days_between(first: str, last: str) -> int:
    try:
        return (datetime.strptime(last, "%Y-%m-%d") - datetime.strptime(first, "%Y-%m-%d")).days
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Pre-built display rows
# ---------------------------------------------------------------------------
def _ticket_date_range(ticket_ids: list[str]) -> tuple[str, str]:
    """Return (first_seen, last_seen) derived from ticket created_at timestamps."""
    dates = sorted(
        TICKETS_BY_ID[tid]["created_at"]
        for tid in ticket_ids
        if tid in TICKETS_BY_ID and TICKETS_BY_ID[tid].get("created_at")
    )
    return (dates[0] if dates else "", dates[-1] if dates else "")


def _malicious_row(r: dict) -> dict:
    country = r.get("country", "")
    first, last = r.get("first_seen", ""), r.get("last_seen", "")
    return {
        "ip": r["ip"],
        "country": country,
        "country_flag": country_flag(country),
        "ticket_count": r.get("ticket_count", 0),
        "days_active": days_between(first, last),
        "attack_types": r.get("attack_types", []),
        "attack_str": ", ".join(fmt_attack(a) for a in r.get("attack_types", [])),
        "blocklists": r.get("blocklists", []),
        "blocklist_str": ", ".join(r.get("blocklists", [])) or "—",
        "isp": r.get("isp") or "—",
        "asn": str(r.get("asn") or "—"),
        "usage_type": r.get("usage_type") or "—",
        "org_name": (r.get("org") or {}).get("name") or "—",
        "org_icon": (r.get("org") or {}).get("icon") or "",
        "org_category": (r.get("org") or {}).get("category") or "",
        "summaries": (r.get("summaries") or [])[:3],
        "first_seen": first,
        "last_seen": last,
    }


_FP_GOV_ACTORS: frozenset[str] = frozenset({"cisa_cyhy"})
_FP_SCANNER_ACTORS: frozenset[str] = frozenset(
    {
        "censys",
        "rapid7",
        "shadowserver",
        "qualys",
        "binaryedge",
        "netspi",
        "stretchoid",
        "onyphe",
        "leakix",
        "nessus",
    }
)


def _fp_category(r: dict) -> tuple[str, str]:
    """Return (display_label, category_key) for an FP record.

    Derives a richer category from disposition + actor since both
    gov scans and commercial scanners carry disposition='false_positive'
    but represent meaningfully different signal types.
    """
    disposition = r.get("disposition") or ""
    actor = r.get("actor") or ""

    if disposition == "benign_true_positive":
        return "Benign True Positive", "benign_true_positive"
    if actor in _FP_GOV_ACTORS:
        return "Gov Scan", "gov_scan"
    if actor in _FP_SCANNER_ACTORS:
        actor_label = actor.replace("_", " ").title()
        return f"Auth Scanner · {actor_label}", "auth_scanner"
    return "False Positive", "false_positive"


def _fp_row(r: dict) -> dict:
    ticket_ids = [str(tid) for tid in (r.get("ticket_ids") or [])]
    first_seen, last_seen = _ticket_date_range(ticket_ids)
    category, category_raw = _fp_category(r)
    return {
        "ip": r["ip"],
        "category": category,
        "category_raw": category_raw,
        "threat_type": r.get("threat_type") or "—",
        "actor": r.get("actor") or "—",
        "score": int(r.get("score") or 0),
        "org_name": (r.get("org") or {}).get("name") or "—",
        "org_icon": (r.get("org") or {}).get("icon") or "",
        "org_category": (r.get("org") or {}).get("category") or "",
        "ticket_count": len(ticket_ids),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _infra_row(r: dict) -> dict:
    _org = r.get("org") or {}
    org = _org if isinstance(_org, dict) else {}
    profile = PROFILES_BY_IP.get(r["ip"])
    return {
        "ip": r["ip"],
        "org_name": org.get("name") or "—",
        "org_icon": org.get("icon") or "",
        "org_category": org.get("category") or "",
        "actor": r.get("actor") or "",
        "first_seen": r.get("first_seen") or "",
        "last_seen": r.get("last_seen") or "",
        "ticket_count": len(r.get("ticket_ids") or []),
        "protocols_str": ", ".join(r.get("protocols_seen") or []),
        "attacks_count": len(r.get("attacks_against") or []),
        "has_profile": profile is not None,
        "profile_hostname": profile.get("hostname") if profile else None,
        "profile_role": profile.get("role") if profile else None,
        "profile_os": profile.get("os_family") if profile else None,
    }


def _dns_resolver_row(r: dict) -> dict:
    ip = r["ip"]
    ticket_ids = [str(tid) for tid in (r.get("ticket_ids") or [])]
    meta = _KNOWN_DNS_RESOLVERS.get(ip, {})
    org = r.get("org") or {}
    first_seen, last_seen = _ticket_date_range(ticket_ids)
    return {
        "ip": ip,
        "name": meta.get("name") or org.get("name") or "—",
        "provider": meta.get("provider") or org.get("name") or "—",
        "org_icon": org.get("icon") or "",
        "org_category": org.get("category") or "",
        "ticket_count": len(ticket_ids),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


def _undetermined_row(r: dict) -> dict:
    ticket_ids = [str(tid) for tid in (r.get("ticket_ids") or [])]
    first_seen, last_seen = _ticket_date_range(ticket_ids)
    return {
        "ip": r["ip"],
        "org_name": (r.get("org") or {}).get("name") or "—",
        "org_icon": (r.get("org") or {}).get("icon") or "",
        "org_category": (r.get("org") or {}).get("category") or "",
        "score": int(r.get("score") or 0),
        "signals": r.get("signals") or [],
        "signals_str": ", ".join(r.get("signals") or []),
        "ticket_count": len(ticket_ids),
        "first_seen": first_seen,
        "last_seen": last_seen,
    }


MALICIOUS_ROWS: list[dict] = sorted(
    [_malicious_row(r) for r in _raw_malicious],
    key=lambda r: r["ticket_count"],
    reverse=True,
)
FP_ROWS: list[dict] = sorted(
    [_fp_row(r) for r in _raw_fp],
    key=lambda r: r["score"],
    reverse=True,
)
INFRA_ROWS: list[dict] = sorted(
    [_infra_row(r) for r in _raw_infra],
    key=lambda r: r["ticket_count"],
    reverse=True,
)
DNS_RESOLVER_ROWS: list[dict] = sorted(
    [_dns_resolver_row(r) for r in DNS_RESOLVER_BY_IP.values()],
    key=lambda r: r["ticket_count"],
    reverse=True,
)
UNDETERMINED_ROWS: list[dict] = sorted(
    [_undetermined_row(r) for r in _raw_undetermined],
    key=lambda r: r["score"],
    reverse=True,
)

# ---------------------------------------------------------------------------
# Filter facets
# ---------------------------------------------------------------------------
ALL_ATTACK_TYPES: list[str] = sorted(
    {at for r in _raw_malicious for at in r.get("attack_types", [])}
)
ALL_BLOCKLISTS: list[str] = sorted({bl for r in _raw_malicious for bl in r.get("blocklists", [])})
ALL_FP_CATEGORIES: list[str] = sorted({_fp_category(r)[1] for r in _raw_fp})
ALL_INFRA_CATEGORIES: list[str] = sorted(
    {r.get("org_category", "") for r in INFRA_ROWS if r.get("org_category")}
)


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------
def get_tickets_for_ip(ip: str) -> list[dict]:
    """Return full ticket dicts for an IP, sorted newest-first."""
    ticket_ids = TICKETS_BY_IP.get(ip, [])
    tickets = [TICKETS_BY_ID[tid] for tid in ticket_ids if tid in TICKETS_BY_ID]
    return sorted(tickets, key=lambda t: t.get("created_at", ""), reverse=True)


def classify_ip(ip: str) -> str:
    """Return 'malicious'|'infra'|'dns_resolver'|'fp'|'undetermined'|'observed'|'unknown'."""
    if ip in MALICIOUS_BY_IP:
        return "malicious"
    if ip in INFRA_BY_IP:
        return "infra"
    if ip in DNS_RESOLVER_BY_IP:
        return "dns_resolver"
    if ip in FP_BY_IP:
        return "fp"
    if ip in UNDETERMINED_BY_IP:
        return "undetermined"
    if TICKETS_BY_IP.get(ip):
        return "observed"
    return "unknown"
