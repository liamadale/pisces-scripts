"""Mantis aggregation functions for the dashboard (in-memory, instant)."""

import collections

from apps.mantis_web.data import INFRA_ROWS, MALICIOUS_ROWS, _raw_tickets


def _filter_tickets(since: str, until: str) -> list:
    """Filter _raw_tickets by created_at date range."""
    tickets = _raw_tickets
    if since:
        tickets = [t for t in tickets if (t.get("created_at", "") or "") >= since]
    if until:
        tickets = [t for t in tickets if (t.get("created_at", "") or "") <= until + "T23:59:59"]
    return tickets


def _filter_malicious(since: str, until: str) -> list:
    """Filter MALICIOUS_ROWS by last_seen date range."""
    rows = MALICIOUS_ROWS
    if since:
        rows = [r for r in rows if (r.get("last_seen", "") or "") >= since]
    if until:
        rows = [r for r in rows if (r.get("first_seen", "") or "") <= until]
    return rows


def agg_mantis_attack_types(since: str = "", until: str = "") -> list:
    """Counter over attack_types in MALICIOUS_ROWS."""
    counter = collections.Counter()
    for row in _filter_malicious(since, until):
        for at in row.get("attack_types", []):
            counter[at] += 1
    return [{"name": k.replace("_", " ").title(), "value": v} for k, v in counter.most_common()]


def agg_mantis_timeline(since: str = "", until: str = "") -> dict:
    """Monthly ticket volume from _raw_tickets."""
    counter = collections.Counter()
    for t in _filter_tickets(since, until):
        created = t.get("created_at", "")
        if created and len(created) >= 7:
            counter[created[:7]] += 1
    months = sorted(counter.keys())
    return {"months": months, "counts": [counter[m] for m in months]}


def agg_mantis_top_ips(since: str = "", until: str = "", n: int = 10) -> list:
    """Top N malicious IPs by ticket count."""
    return sorted(_filter_malicious(since, until), key=lambda r: -r.get("tickets", 0))[:n]


def agg_mantis_infra_count() -> int:
    """Total number of known infrastructure IPs."""
    return len(INFRA_ROWS)
