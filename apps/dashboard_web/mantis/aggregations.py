"""Mantis aggregation functions for the dashboard (in-memory, instant)."""

import collections

from apps.mantis_web.data import INFRA_ROWS, MALICIOUS_ROWS, _raw_tickets


def agg_mantis_attack_types() -> list:
    """Counter over attack_types in MALICIOUS_ROWS."""
    counter = collections.Counter()
    for row in MALICIOUS_ROWS:
        for at in row.get("attack_types", []):
            counter[at] += 1
    return [{"name": k.replace("_", " ").title(), "value": v} for k, v in counter.most_common()]


def agg_mantis_timeline() -> dict:
    """Monthly ticket volume from _raw_tickets."""
    counter = collections.Counter()
    for t in _raw_tickets:
        created = t.get("created_at", "")
        if created and len(created) >= 7:
            counter[created[:7]] += 1
    months = sorted(counter.keys())
    return {"months": months, "counts": [counter[m] for m in months]}


def agg_mantis_blocklists() -> dict:
    """Counter over blocklists in MALICIOUS_ROWS."""
    counter = collections.Counter()
    for row in MALICIOUS_ROWS:
        for bl in row.get("blocklists", []):
            counter[bl] += 1
    items = counter.most_common()
    return {
        "labels": [k for k, _ in items],
        "counts": [v for _, v in items],
    }


def agg_mantis_top_ips(n: int = 10) -> list:
    """Top N malicious IPs by ticket count."""
    return sorted(MALICIOUS_ROWS, key=lambda r: -r.get("tickets", 0))[:n]


def agg_mantis_infra_count() -> int:
    """Total number of known infrastructure IPs."""
    return len(INFRA_ROWS)
