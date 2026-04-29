"""Startup data loading and per-request computation for Mantis Explorer."""

import os
import re
from collections import defaultdict
from datetime import date, timedelta
from functools import lru_cache

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))

# ---------------------------------------------------------------------------
# Raw tickets — reuse mantis_web's already-parsed list in hub mode so we
# don't parse the JSON twice.  Falls back to loading independently when
# running standalone (mantis_web.data will load itself in that process).
# ---------------------------------------------------------------------------
from apps.mantis_web.data import TICKETS_BY_ID  # noqa: E402, F401
from apps.mantis_web.data import _raw_tickets as RAW_TICKETS  # noqa: E402
from src.mantis.activity_report import (  # noqa: E402
    StudentStats,
    _filter_by_date_range,
    _format_date_range,
    build_report,
)

# ---------------------------------------------------------------------------
# Slug maps — built once at startup from all category values in the corpus
# ---------------------------------------------------------------------------


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _build_slug_maps(tickets: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    """Return (slug→org, org→slug) for every unique category value."""
    orgs: set[str] = set()
    for t in tickets:
        cat = t.get("category", "")
        if cat:
            orgs.add(cat)

    slug_to_org: dict[str, str] = {}
    org_to_slug: dict[str, str] = {}
    for org in sorted(orgs):
        slug = _slugify(org)
        # Collision avoidance
        if slug in slug_to_org:
            n = 2
            while f"{slug}-{n}" in slug_to_org:
                n += 1
            slug = f"{slug}-{n}"
        slug_to_org[slug] = org
        org_to_slug[org] = slug
    return slug_to_org, org_to_slug


SLUG_TO_ORG, ORG_TO_SLUG = _build_slug_maps(RAW_TICKETS)

# ---------------------------------------------------------------------------
# Per-request computation with caching
# ---------------------------------------------------------------------------


def parse_date_params(args: object) -> tuple[str, str]:
    """Extract and validate since/until from request.args.

    Returns ("", "") for absent or invalid values so callers can pass
    strings directly to get_report() without additional validation.
    """

    def _safe(key: str) -> str:
        v = getattr(args, "get", lambda k, d="": d)(key, "").strip()
        try:
            date.fromisoformat(v)
            return v
        except ValueError:
            return ""

    return _safe("since"), _safe("until")


@lru_cache(maxsize=32)
def get_report(since_str: str, until_str: str) -> dict[int, StudentStats]:
    """Filter RAW_TICKETS by date range and run build_report(). Cached by (since, until)."""
    since = date.fromisoformat(since_str) if since_str else None
    until = date.fromisoformat(until_str) if until_str else None
    filtered = _filter_by_date_range(RAW_TICKETS, since, until)
    return build_report(filtered)


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------


def compute_global_stats(report: dict[int, StudentStats]) -> dict:
    """Summary numbers for the overview stat row."""
    all_orgs: set[str] = set()
    total_tickets = 0
    total_escalations = 0
    total_notes = 0
    all_dates: list[str] = []

    for s in report.values():
        all_orgs.update(s.categories)
        total_tickets += s.tickets_created
        total_escalations += s.escalated_tickets
        total_notes += s.notes_written
        all_dates.extend(ref["created_at"] for ref in s.created_tickets if ref.get("created_at"))

    return {
        "institution_count": len(all_orgs),
        "student_count": len(report),
        "ticket_count": total_tickets,
        "escalation_count": total_escalations,
        "note_count": total_notes,
        "date_range": _format_date_range(all_dates),
    }


def _org_aggregate(report: dict[int, StudentStats], q: str = "") -> dict[str, dict]:
    """Build a per-org aggregation dict keyed by raw category name."""
    agg: dict[str, dict] = {}
    for sid, s in report.items():
        for cat in s.categories:
            if q and q.lower() not in cat.lower():
                continue
            if cat not in agg:
                agg[cat] = {
                    "name": cat,
                    "slug": ORG_TO_SLUG.get(cat, _slugify(cat)),
                    "student_ids": set(),
                    "ticket_count": 0,
                    "escalation_count": 0,
                    "note_count": 0,
                    "dates": [],
                }
            d = agg[cat]
            d["student_ids"].add(sid)
            d["ticket_count"] += s.tickets_created
            d["escalation_count"] += s.escalated_tickets
            d["note_count"] += s.notes_written
            d["dates"].extend(
                ref["created_at"] for ref in s.created_tickets if ref.get("created_at")
            )
    return agg


def compute_org_rows(
    report: dict[int, StudentStats],
    q: str = "",
    sort: str = "tickets",
    order: str = "desc",
) -> list[dict]:
    """Return institution table rows, sorted and optionally name-filtered."""
    agg = _org_aggregate(report, q=q)
    rows = []
    for d in agg.values():
        rows.append(
            {
                "name": d["name"],
                "slug": d["slug"],
                "student_count": len(d["student_ids"]),
                "ticket_count": d["ticket_count"],
                "escalation_count": d["escalation_count"],
                "note_count": d["note_count"],
                "date_range": _format_date_range(d["dates"]),
            }
        )

    key_fn = {
        "name": lambda r: r["name"].lower(),
        "students": lambda r: r["student_count"],
        "tickets": lambda r: r["ticket_count"],
        "escalated": lambda r: r["escalation_count"],
        "notes": lambda r: r["note_count"],
    }.get(sort, lambda r: r["ticket_count"])
    rows.sort(key=key_fn, reverse=(order == "desc"))
    return rows


def compute_timeline_data(report: dict[int, StudentStats]) -> dict:
    """Auto-granularity timeline data for ECharts.

    Mirrors the _plot_ticket_timeline logic from activity_report.py but
    returns a JSON-serialisable dict instead of drawing to the terminal.

    Returns:
        {"labels": [...], "counts": [...], "granularity": "daily"|"weekly"|"monthly"}
        or {"labels": [], "counts": [], "granularity": "daily"} when no dated tickets.
    """
    raw_dates: list[str] = [
        ref["created_at"]
        for s in report.values()
        for ref in s.created_tickets
        if ref.get("created_at") and len(ref["created_at"]) >= 10
    ]
    if not raw_dates:
        return {"labels": [], "counts": [], "granularity": "daily"}

    parsed = sorted(date.fromisoformat(d[:10]) for d in raw_dates)
    span_days = (parsed[-1] - parsed[0]).days

    if span_days <= 35:
        granularity = "daily"
        label_fmt = "%b %d"
        bucket_fn = lambda d: d  # noqa: E731
    elif span_days <= 365:
        granularity = "weekly"
        label_fmt = "%b %d"
        bucket_fn = lambda d: d - timedelta(days=d.weekday())  # noqa: E731
    else:
        granularity = "monthly"
        label_fmt = "%b '%y"
        bucket_fn = lambda d: d.replace(day=1)  # noqa: E731

    buckets: dict[date, int] = defaultdict(int)
    for d in parsed:
        buckets[bucket_fn(d)] += 1

    # Fill gaps
    all_buckets = sorted(buckets)
    first, last = all_buckets[0], all_buckets[-1]
    full_range: list[date] = []
    if granularity == "daily":
        cursor = first
        while cursor <= last:
            full_range.append(cursor)
            cursor += timedelta(days=1)
    elif granularity == "weekly":
        cursor = first
        while cursor <= last:
            full_range.append(cursor)
            cursor += timedelta(weeks=1)
    else:
        y, m = first.year, first.month
        while date(y, m, 1) <= last:
            full_range.append(date(y, m, 1))
            m += 1
            if m > 12:
                m, y = 1, y + 1

    return {
        "labels": [b.strftime(label_fmt) for b in full_range],
        "counts": [buckets.get(b, 0) for b in full_range],
        "granularity": granularity,
    }


def compute_escalation_data(report: dict[int, StudentStats]) -> dict:
    """Per-org escalation data for the grouped bar chart.

    Returns:
        {"orgs": [...], "totals": [...], "escalated": [...]}
        sorted by total tickets descending.
    """
    agg = _org_aggregate(report)
    rows = sorted(agg.values(), key=lambda d: d["ticket_count"], reverse=True)
    return {
        "orgs": [d["name"] for d in rows],
        "totals": [d["ticket_count"] for d in rows],
        "escalated": [d["escalation_count"] for d in rows],
    }


def compute_org_report(report: dict[int, StudentStats], org_name: str) -> dict[int, StudentStats]:
    """Filter report to students who have at least one ticket in org_name's category."""
    return {k: v for k, v in report.items() if org_name in v.categories}


def compute_org_stats(org_report: dict[int, StudentStats]) -> dict:
    """Summary numbers for the org-detail stat row."""
    total_tickets = sum(s.tickets_created for s in org_report.values())
    total_escalations = sum(s.escalated_tickets for s in org_report.values())
    total_notes = sum(s.notes_written for s in org_report.values())
    all_dates = [
        ref["created_at"]
        for s in org_report.values()
        for ref in s.created_tickets
        if ref.get("created_at")
    ]
    return {
        "student_count": len(org_report),
        "ticket_count": total_tickets,
        "escalation_count": total_escalations,
        "note_count": total_notes,
        "date_range": _format_date_range(all_dates),
    }


def sort_students(
    org_report: dict[int, StudentStats],
    sort: str = "activity",
    order: str = "desc",
    q: str = "",
) -> list[tuple[int, StudentStats]]:
    """Return (reporter_id, StudentStats) pairs sorted and optionally name-filtered."""
    pairs = list(org_report.items())
    if q:
        pairs = [(k, v) for k, v in pairs if q.lower() in v.name.lower()]

    key_fn = {
        "name": lambda p: p[1].name.lower(),
        "tickets": lambda p: p[1].tickets_created,
        "escalated": lambda p: p[1].escalated_tickets,
        "notes": lambda p: p[1].notes_written,
        "activity": lambda p: p[1].total_activity,
    }.get(sort, lambda p: p[1].total_activity)

    pairs.sort(key=key_fn, reverse=(order != "asc" and sort != "name"))
    return pairs
