"""Startup data loading and in-memory indices for the Threat Modeling app."""

import json
import os
from collections import defaultdict
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
# src/mantis/threat_model_web_app/ → go 3 levels up to reach repo root
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(_HERE)))
DATA_DIR = os.path.join(_REPO, "data", "tickets")


def _load(name):
    with open(os.path.join(DATA_DIR, name), encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Raw data
# ---------------------------------------------------------------------------
_raw_tickets   = _load("tickets_index.json")
_raw_malicious = _load("known_malicious_ips.json")
_raw_fp        = _load("fp_ips_detail.json")

# ---------------------------------------------------------------------------
# Indices
# ---------------------------------------------------------------------------
TICKETS_BY_ID = {str(t["id"]): t for t in _raw_tickets}

TICKETS_BY_IP: dict[str, list[str]] = defaultdict(list)
for _t in _raw_tickets:
    for _ip in (_t.get("ips") or []):
        TICKETS_BY_IP[_ip].append(str(_t["id"]))

MALICIOUS_BY_IP: dict[str, dict] = {r["ip"]: r for r in _raw_malicious}
FP_BY_IP:        dict[str, dict] = {r["ip"]: r for r in _raw_fp}


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
        return (
            datetime.strptime(last, "%Y-%m-%d")
            - datetime.strptime(first, "%Y-%m-%d")
        ).days
    except Exception:
        return 0


# ---------------------------------------------------------------------------
# Pre-built display rows
# ---------------------------------------------------------------------------
def _malicious_row(r: dict) -> dict:
    country = r.get("country", "")
    first, last = r.get("first_seen", ""), r.get("last_seen", "")
    return {
        "ip":           r["ip"],
        "country":      country,
        "country_flag": country_flag(country),
        "tickets":      r.get("ticket_count", 0),
        "days_active":  days_between(first, last),
        "attack_types": r.get("attack_types", []),
        "attack_str":   ", ".join(fmt_attack(a) for a in r.get("attack_types", [])),
        "cves":         r.get("cves", []),
        "cve_str":      ", ".join(r.get("cves", [])) or "—",
        "blocklists":   r.get("blocklists", []),
        "blocklist_str": ", ".join(r.get("blocklists", [])) or "—",
        "isp":          r.get("isp") or "—",
        "asn":          str(r.get("asn") or "—"),
        "usage_type":   r.get("usage_type") or "—",
        "summaries":    (r.get("summaries") or [])[:3],
        "first_seen":   first,
        "last_seen":    last,
    }


def _fp_row(r: dict) -> dict:
    return {
        "ip":           r["ip"],
        "category":     (r.get("disposition") or "—").replace("_", " ").title(),
        "category_raw": r.get("disposition") or "",
        "threat_type":  r.get("threat_type") or "—",
        "actor":        r.get("actor") or "—",
        "score":        round(float(r.get("score") or 0), 2),
        "ticket_count": len(r.get("ticket_ids") or []),
    }


MALICIOUS_ROWS: list[dict] = [_malicious_row(r) for r in _raw_malicious]
FP_ROWS:        list[dict] = [_fp_row(r)        for r in _raw_fp]

# ---------------------------------------------------------------------------
# Filter facets
# ---------------------------------------------------------------------------
ALL_ATTACK_TYPES: list[str] = sorted(
    {at for r in _raw_malicious for at in r.get("attack_types", [])}
)
ALL_BLOCKLISTS: list[str] = sorted(
    {bl for r in _raw_malicious for bl in r.get("blocklists", [])}
)
ALL_FP_CATEGORIES: list[str] = sorted(
    {r.get("disposition", "") for r in _raw_fp if r.get("disposition")}
)


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------
def get_tickets_for_ip(ip: str) -> list[dict]:
    """Return full ticket dicts for an IP, sorted newest-first."""
    return sorted(
        [t for t in _raw_tickets if ip in (t.get("ips") or [])],
        key=lambda t: t.get("created_at", ""),
        reverse=True,
    )


def classify_ip(ip: str) -> str:
    """Return 'malicious' | 'fp' | 'observed' | 'unknown'."""
    if ip in MALICIOUS_BY_IP:
        return "malicious"
    if ip in FP_BY_IP:
        return "fp"
    if TICKETS_BY_IP.get(ip):
        return "observed"
    return "unknown"
