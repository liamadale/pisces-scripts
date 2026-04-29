#!/usr/bin/env python3
"""
Student activity report — counts tickets created and notes written per student.

Students are defined as any reporter who has never acted as a ticket handler
anywhere in the corpus (mirrors the handler_registry logic in mantis_index.py).

Reads from the local offline index by default; pass --live to fetch from the
REST API instead (requires MANTIS_API_TOKEN + MANTIS_API_URL).

When --student matches exactly one name, a detailed view is shown with ticket
titles and links. When it matches multiple, the user is prompted to pick one.

Usage:
    python src/mantis/activity_report.py
    python src/mantis/activity_report.py --live
    python src/mantis/activity_report.py --sort tickets
    python src/mantis/activity_report.py --project bonney-lake
    python src/mantis/activity_report.py --student alice
    python src/mantis/activity_report.py --student alice --graph
    python src/mantis/activity_report.py --org 'bellevue college'
    python src/mantis/activity_report.py --org 'bellevue college' --student alice
    python src/mantis/activity_report.py --since 2025-01-01 --until 2025-04-30
    python src/mantis/activity_report.py --input data/tickets/indexed/tickets_index.json
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import urllib3
from dotenv import load_dotenv
from rich import box
from rich.console import Console
from rich.rule import Rule
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_INDEX = os.path.join(_BASE, "data", "tickets", "indexed", "tickets_index.json")

console = Console()


def _ordinal(n: int) -> str:
    """Return an integer with its ordinal suffix: 1st, 2nd, 3rd, 4th…"""
    if 11 <= (n % 100) <= 13:
        suffix = "th"
    else:
        suffix = {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def _format_date_range(date_strs: list[str]) -> str:
    """Format a collection of YYYY-MM-DD strings as a human-readable span.

    Returns strings like "Jan 1st – Apr 28th" for same-year ranges, or
    "Jan 1st, 2024 – Apr 28th, 2025" when the range crosses calendar years.
    Returns an empty string when no valid dates are present.
    """
    valid = [d for d in date_strs if d and len(d) >= 10]
    if not valid:
        return ""
    parsed = sorted(date.fromisoformat(d[:10]) for d in valid)
    first, last = parsed[0], parsed[-1]
    cross_year = first.year != last.year

    def _fmt(d: date) -> str:
        base = f"{d.strftime('%b')} {_ordinal(d.day)}"
        return f"{base}, {d.year}" if cross_year else base

    if first == last:
        return _fmt(first)
    return f"{_fmt(first)} – {_fmt(last)}"


def _filter_by_date_range(
    tickets: list[dict],
    since: date | None,
    until: date | None,
) -> list[dict]:
    """Return only tickets whose created_at falls within [since, until].

    Tickets with no or unparseable created_at are kept so data is not silently lost.
    """
    if not since and not until:
        return tickets
    result = []
    for t in tickets:
        raw = (t.get("created_at") or "")[:10]
        if not raw:
            result.append(t)
            continue
        try:
            d = date.fromisoformat(raw)
        except ValueError:
            result.append(t)
            continue
        if since and d < since:
            continue
        if until and d > until:
            continue
        result.append(t)
    return result


# Minimal ticket ref stored per student — id, summary, url, status, created_at
_TicketRef = dict


@dataclass
class StudentStats:
    """Activity data for a single student reporter."""

    name: str
    created_tickets: list[_TicketRef] = field(default_factory=list)
    # Tickets they left notes on that they did NOT create (keyed by id to deduplicate)
    _noted: dict[str, _TicketRef] = field(default_factory=dict, repr=False)
    notes_written: int = 0
    projects: set[str] = field(default_factory=set)

    @property
    def tickets_created(self) -> int:
        return len(self.created_tickets)

    @property
    def noted_tickets(self) -> list[_TicketRef]:
        """Unique tickets this student commented on but did not create."""
        return list(self._noted.values())

    escalated_tickets: int = 0
    categories: set[str] = field(default_factory=set)

    @property
    def total_activity(self) -> int:
        return self.tickets_created + self.notes_written

    def add_noted(self, ticket: _TicketRef) -> None:
        """Record a ticket this student left a note on (deduplicates by id)."""
        tid = ticket["id"]
        if tid not in self._noted:
            self._noted[tid] = ticket


def _ticket_ref(ticket: dict) -> _TicketRef:
    """Extract the minimal displayable fields from a normalized ticket dict."""
    return {
        "id": ticket.get("id", ""),
        "summary": ticket.get("summary", ""),
        "url": ticket.get("url", ""),
        "status": ticket.get("status", ""),
        "created_at": ticket.get("created_at", ""),
        "is_escalated": bool(ticket.get("is_escalated")),
    }


def _load_offline(path: str) -> list[dict]:
    """Load normalized tickets from the offline index JSON."""
    if not os.path.exists(path):
        console.print(f"[red]Offline index not found: {path}[/red]")
        console.print("[dim]Run: python src/mantis/mantis_index.py[/dim]")
        sys.exit(1)
    with open(path) as fh:
        return json.load(fh)


def _load_live(project_filter: str | None) -> list[dict]:
    """Fetch all tickets from the MantisBT REST API."""
    import requests

    from src.mantis.mantis_search import _normalize_issue

    api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    api_token = os.environ.get("MANTIS_API_TOKEN", "")
    if not api_url or not api_token:
        console.print("[red]MANTIS_API_URL and MANTIS_API_TOKEN are required for --live[/red]")
        sys.exit(1)

    headers = {"Authorization": api_token}
    all_raw: list[dict] = []
    page = 1

    console.print("[dim]Fetching tickets from Mantis REST API...[/dim]")
    while True:
        resp = requests.get(
            f"{api_url}/api/rest/issues",
            headers=headers,
            params={"page_size": 200, "page": page},
            timeout=30,
            verify=False,
        )
        if not resp.ok:
            console.print(f"[red]API error {resp.status_code} on page {page}[/red]")
            break
        data = resp.json()
        issues = data.get("issues", [])
        if not issues:
            break
        all_raw.extend(issues)
        total = data.get("total_count")
        if total and page * 200 >= total:
            break
        if len(issues) < 200:
            break
        page += 1

    console.print(f"[dim]Fetched {len(all_raw)} tickets — normalizing...[/dim]")
    handler_registry: set[int] = {
        issue["handler"]["id"] for issue in all_raw if issue.get("handler")
    }
    tickets = [_normalize_issue(issue, api_url, handler_registry) for issue in all_raw]

    if project_filter:
        tickets = [t for t in tickets if project_filter.lower() in t.get("project", "").lower()]

    return tickets


def build_report(
    tickets: list[dict],
    project_filter: str | None = None,
) -> dict[int, StudentStats]:
    """Aggregate per-student activity from a normalized ticket list.

    Args:
        tickets: Normalized ticket dicts from the offline index or live API.
        project_filter: Optional substring filter on the project/city field.

    Returns:
        Mapping of reporter_id → StudentStats, excluding known handlers.
    """
    if project_filter:
        tickets = [t for t in tickets if project_filter.lower() in t.get("project", "").lower()]

    # Rebuild handler registry from this corpus
    handler_ids: set[int] = set()
    for t in tickets:
        h = t.get("handler")
        if h and h.get("id"):
            handler_ids.add(h["id"])
        for note in t.get("notes", []):
            if note.get("is_admin_note"):
                handler_ids.add(note["reporter"]["id"])

    stats: dict[int, StudentStats] = defaultdict(lambda: StudentStats(name=""))

    for ticket in tickets:
        reporter = ticket.get("reporter", {})
        reporter_id = reporter.get("id", 0)
        reporter_name = reporter.get("name", "unknown")
        project = ticket.get("project", "")
        ref = _ticket_ref(ticket)

        if reporter_id not in handler_ids:
            stats[reporter_id].name = reporter_name
            stats[reporter_id].created_tickets.append(ref)
            if project:
                stats[reporter_id].projects.add(project)
            if ticket.get("is_escalated"):
                stats[reporter_id].escalated_tickets += 1
            category = ticket.get("category", "")
            if category:
                stats[reporter_id].categories.add(category)

        for note in ticket.get("notes", []):
            note_reporter = note.get("reporter", {})
            note_id = note_reporter.get("id", 0)
            note_name = note_reporter.get("name", "unknown")

            if note_id in handler_ids:
                continue

            stats[note_id].name = note_name
            stats[note_id].notes_written += 1
            if project:
                stats[note_id].projects.add(project)
            # Only track as "noted" if they didn't create it
            if note_id != reporter_id:
                stats[note_id].add_noted(ref)

    return dict(stats)


def _pick_student(matches: list[tuple[int, StudentStats]]) -> tuple[int, StudentStats] | None:
    """Prompt the user to select one student from a list of matches."""
    console.print(f"\n[yellow]Found {len(matches)} students matching that name:[/yellow]\n")
    for i, (_, s) in enumerate(matches, 1):
        console.print(
            f"  [cyan]{i}[/cyan]. {s.name} "
            f"— {s.tickets_created} ticket(s), {s.notes_written} note(s)"
        )
    console.print()

    while True:
        try:
            raw = input("Select a student (number), or press Enter to show all: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if raw == "":
            return None

        if raw.isdigit() and 1 <= int(raw) <= len(matches):
            return matches[int(raw) - 1]

        console.print(f"[red]Enter a number between 1 and {len(matches)}.[/red]")


def _pick_org(matches: list[str]) -> str | None:
    """Prompt the user to select one institution from a list of matches."""
    console.print(f"\n[yellow]Found {len(matches)} institutions matching that name:[/yellow]\n")
    for i, name in enumerate(matches, 1):
        console.print(f"  [cyan]{i}[/cyan]. {name}")
    console.print()

    while True:
        try:
            raw = input("Select an institution (number), or press Enter to show all: ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print()
            return None

        if raw == "":
            return None

        if raw.isdigit() and 1 <= int(raw) <= len(matches):
            return matches[int(raw) - 1]

        console.print(f"[red]Enter a number between 1 and {len(matches)}.[/red]")


def display_org_report(
    stats: dict[int, StudentStats],
    org_filter: str,
    sort_by: str = "activity",
    student_filter: str | None = None,
    show_graph: bool = False,
) -> None:
    """Render the activity report for a single institution.

    Finds all unique ticket categories matching org_filter (substring,
    case-insensitive). If multiple categories match, prompts the user to pick
    one or show all. Then renders the same summary table as display_report(),
    scoped to students whose tickets belong to the matched category/categories.

    If student_filter is also provided, further narrows to a specific student
    within the institution and shows the detail view.

    Args:
        stats: Full per-student stats from build_report().
        org_filter: Substring to match against ticket category names.
        sort_by: Column to sort the summary table by.
        student_filter: Optional student name substring for further drill-down.
        show_graph: Whether to show the submission graph in detail view.
    """
    # Collect all unique categories across the corpus
    all_categories: list[str] = sorted(
        {cat for s in stats.values() for cat in s.categories},
        key=str.lower,
    )
    matching_cats = [c for c in all_categories if org_filter.lower() in c.lower()]

    if not matching_cats:
        console.print(f"[yellow]No institution matching '{org_filter}' found.[/yellow]")
        console.print(f"[dim]Known institutions: {', '.join(all_categories) or 'none'}[/dim]")
        return

    # Disambiguate if multiple categories match
    if len(matching_cats) == 1:
        chosen_cats = matching_cats
    else:
        chosen = _pick_org(matching_cats)
        chosen_cats = [chosen] if chosen is not None else matching_cats

    org_label = chosen_cats[0] if len(chosen_cats) == 1 else org_filter

    # Filter students who have tickets in any of the chosen categories
    org_stats = {k: v for k, v in stats.items() if v.categories & set(chosen_cats)}

    if not org_stats:
        console.print(f"[yellow]No students found for institution '{org_label}'.[/yellow]")
        return

    all_dates = [ref["created_at"] for s in org_stats.values() for ref in s.created_tickets]
    date_range = _format_date_range(all_dates)
    date_part = f" · {date_range}" if date_range else ""
    console.print(
        Rule(f"[bold]{org_label}[/bold]  [dim]({len(org_stats)} students{date_part})[/dim]")
    )

    if student_filter:
        # Delegate to the normal student-filter path, scoped to this org
        display_report(
            org_stats,
            sort_by=sort_by,
            student_filter=student_filter,
            show_graph=show_graph,
        )
    else:
        display_report(org_stats, sort_by=sort_by)
        if show_graph:
            console.print()
            draw_org_graph(org_stats, org_label)


def display_student_detail(student: StudentStats, show_graph: bool = False) -> None:
    """Render a detailed activity breakdown for a single student."""
    console.print(Rule(f"[cyan]{student.name}[/cyan]"))
    escalated_str = (
        f"   Escalated: [red]{student.escalated_tickets}[/red]" if student.escalated_tickets else ""
    )
    console.print(
        f"  Tickets created: [green]{student.tickets_created}[/green]"
        f"{escalated_str}   "
        f"Notes written: [yellow]{student.notes_written}[/yellow]   "
        f"Total activity: [bold]{student.total_activity}[/bold]"
    )
    if student.projects:
        console.print(f"  Projects: [dim]{', '.join(sorted(student.projects))}[/dim]")
    console.print()

    if student.created_tickets:
        created = Table(title="Tickets Created", box=box.SIMPLE, show_header=True)
        created.add_column("#", style="dim", no_wrap=True)
        created.add_column("Summary", ratio=3)
        created.add_column("Status", no_wrap=True)
        created.add_column("Created", no_wrap=True)
        created.add_column("Link", style="blue")

        for ref in sorted(
            student.created_tickets,
            key=lambda r: int(r["id"]) if r["id"].isdigit() else 0,
            reverse=True,
        ):
            created.add_row(
                ref["id"],
                ref["summary"] or "—",
                ref["status"] or "—",
                ref["created_at"] or "—",
                ref["url"],
            )
        console.print(created)

    noted = student.noted_tickets
    if noted:
        noted_table = Table(
            title="Tickets Commented On (not created by this student)", box=box.SIMPLE
        )
        noted_table.add_column("#", style="dim", no_wrap=True)
        noted_table.add_column("Summary", ratio=3)
        noted_table.add_column("Status", no_wrap=True)
        noted_table.add_column("Link", style="blue")

        for ref in sorted(
            noted, key=lambda r: int(r["id"]) if r["id"].isdigit() else 0, reverse=True
        ):
            noted_table.add_row(
                ref["id"],
                ref["summary"] or "—",
                ref["status"] or "—",
                ref["url"],
            )
        console.print(noted_table)

    if show_graph:
        console.print()
        draw_submission_graph(student)


def _plot_ticket_timeline(date_strs: list[str], title: str) -> None:
    """Render a terminal line graph of ticket submissions over time.

    Accepts a flat list of YYYY-MM-DD strings (duplicates allowed — each
    represents one ticket). Granularity is chosen automatically:
      - ≤ 5 weeks  → daily
      - ≤ 12 months → weekly (Mon-anchored)
      - > 12 months → monthly

    The graph width is capped to the terminal width minus a small margin.
    """
    import plotext as plt

    parsed = sorted(date.fromisoformat(d) for d in date_strs)
    span_days = (parsed[-1] - parsed[0]).days

    if span_days <= 35:
        granularity = "day"
        label_fmt = "%b %d"
        bucket_fn = lambda d: d  # noqa: E731
    elif span_days <= 365:
        granularity = "week"
        label_fmt = "%b %d"
        bucket_fn = lambda d: d - timedelta(days=d.weekday())  # noqa: E731
    else:
        granularity = "month"
        label_fmt = "%b '%y"
        bucket_fn = lambda d: d.replace(day=1)  # noqa: E731

    buckets: dict[date, int] = defaultdict(int)
    for d in parsed:
        buckets[bucket_fn(d)] += 1

    # Fill gaps so the x-axis is contiguous
    all_buckets = sorted(buckets)
    first, last = all_buckets[0], all_buckets[-1]
    if granularity == "day":
        cursor, step = first, timedelta(days=1)
        full_range: list[date] = []
        while cursor <= last:
            full_range.append(cursor)
            cursor += step
    elif granularity == "week":
        cursor, step = first, timedelta(weeks=1)
        full_range = []
        while cursor <= last:
            full_range.append(cursor)
            cursor += step
    else:
        full_range = []
        y, m = first.year, first.month
        while date(y, m, 1) <= last:
            full_range.append(date(y, m, 1))
            m += 1
            if m > 12:
                m, y = 1, y + 1

    counts = [buckets.get(b, 0) for b in full_range]
    labels = [b.strftime(label_fmt) for b in full_range]
    # Use numeric x indices — passing formatted strings causes plotext to attempt
    # date parsing which fails for short formats like "Jan 12".
    x_indices = list(range(len(counts)))

    try:
        term_width = os.get_terminal_size().columns
    except OSError:
        term_width = 100
    plot_width = max(60, min(term_width - 4, 160))

    tick_step = max(1, len(labels) // (plot_width // 10))
    tick_positions = x_indices[::tick_step]
    tick_labels = labels[::tick_step]

    plt.clf()
    plt.plot_size(plot_width, 14)
    plt.theme("dark")
    plt.title(f"{title}  ({granularity}ly)")
    plt.xlabel(granularity.capitalize())
    plt.ylabel("Tickets")
    plt.plot(x_indices, counts, marker="braille")
    plt.xticks(tick_positions, tick_labels)
    plt.show()
    console.print(
        f"  [dim]{len(parsed)} ticket(s) · "
        f"{full_range[0].strftime('%Y-%m-%d')} → {full_range[-1].strftime('%Y-%m-%d')} "
        f"· {granularity}ly buckets[/dim]"
    )


def draw_submission_graph(student: StudentStats) -> None:
    """Render a submission timeline graph for a single student."""
    dated = [
        ref["created_at"]
        for ref in student.created_tickets
        if ref.get("created_at") and len(ref["created_at"]) == 10
    ]
    if not dated:
        console.print("[yellow]No dated tickets — cannot draw graph.[/yellow]")
        return
    _plot_ticket_timeline(dated, f"Ticket Submissions — {student.name}")


def draw_org_graph(org_stats: dict[int, StudentStats], org_label: str) -> None:
    """Render an aggregate submission timeline graph for all students in an org."""
    dated = [
        ref["created_at"]
        for s in org_stats.values()
        for ref in s.created_tickets
        if ref.get("created_at") and len(ref["created_at"]) == 10
    ]
    if not dated:
        console.print("[yellow]No dated tickets — cannot draw graph.[/yellow]")
        return
    _plot_ticket_timeline(dated, f"Ticket Submissions — {org_label}")


def display_report(
    stats: dict[int, StudentStats],
    sort_by: str = "activity",
    student_filter: str | None = None,
    org_filter: str | None = None,
    show_graph: bool = False,
) -> None:
    """Render the student activity report.

    If org_filter is set, delegates to display_org_report() which scopes the
    table to students from that institution (matched by ticket category).
    If student_filter matches exactly one student, shows the detail view.
    If it matches multiple, prompts the user to pick one (or show all).
    With no filter, renders the full summary table.
    """
    if org_filter:
        display_org_report(
            stats,
            org_filter=org_filter,
            sort_by=sort_by,
            student_filter=student_filter,
            show_graph=show_graph,
        )
        return

    if student_filter:
        matches = [(k, v) for k, v in stats.items() if student_filter.lower() in v.name.lower()]

        if not matches:
            console.print(f"[yellow]No student matching '{student_filter}' found.[/yellow]")
            return

        if len(matches) == 1:
            display_student_detail(matches[0][1], show_graph=show_graph)
            return

        # Multiple matches — prompt
        chosen = _pick_student(matches)
        if chosen is not None:
            display_student_detail(chosen[1], show_graph=show_graph)
            return

        # User pressed Enter — fall through and show all matches in summary table
        stats = dict(matches)

    rows = list(stats.values())

    if sort_by == "tickets":
        rows.sort(key=lambda s: s.tickets_created, reverse=True)
    elif sort_by == "notes":
        rows.sort(key=lambda s: s.notes_written, reverse=True)
    elif sort_by == "name":
        rows.sort(key=lambda s: s.name.lower())
    else:
        rows.sort(key=lambda s: s.total_activity, reverse=True)

    all_dates = [ref["created_at"] for s in rows for ref in s.created_tickets]
    date_range = _format_date_range(all_dates)
    title = f"Student Activity Report ({len(rows)} students)"
    if date_range:
        title += f"  ·  {date_range}"

    table = Table(
        title=title,
        box=box.SIMPLE,
        show_footer=True,
    )
    table.add_column("Student", style="cyan", footer="TOTAL")
    table.add_column(
        "Tickets Created",
        justify="right",
        style="green",
        footer=str(sum(s.tickets_created for s in rows)),
    )
    table.add_column(
        "Escalated",
        justify="right",
        style="red",
        footer=str(sum(s.escalated_tickets for s in rows)),
    )
    table.add_column(
        "Notes Written",
        justify="right",
        style="yellow",
        footer=str(sum(s.notes_written for s in rows)),
    )
    table.add_column(
        "Total Activity",
        justify="right",
        footer=str(sum(s.total_activity for s in rows)),
    )
    table.add_column("Projects", style="dim")

    for s in rows:
        projects_str = ", ".join(sorted(s.projects)) if s.projects else "—"
        escalated_str = str(s.escalated_tickets) if s.escalated_tickets else "—"
        table.add_row(
            s.name,
            str(s.tickets_created),
            escalated_str,
            str(s.notes_written),
            str(s.total_activity),
            projects_str,
        )

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Student Activity Report")
    parser.add_argument(
        "--input",
        default=DEFAULT_INDEX,
        help="Path to tickets_index.json (default: data/tickets/indexed/tickets_index.json)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Fetch from Mantis REST API instead of the offline index",
    )
    parser.add_argument(
        "--project",
        metavar="NAME",
        help="Filter to tickets in projects matching NAME (substring, e.g. bonney-lake)",
    )
    parser.add_argument(
        "--sort",
        choices=["activity", "tickets", "notes", "name"],
        default="activity",
        help="Sort order for the summary table (default: activity)",
    )
    parser.add_argument(
        "--student",
        metavar="NAME",
        help="Filter to a specific student by name (substring, case-insensitive)",
    )
    parser.add_argument(
        "--org",
        metavar="NAME",
        help="Filter to students from a specific institution by category name (substring, "
        "case-insensitive, e.g. 'bellevue college')",
    )
    parser.add_argument(
        "--since",
        metavar="YYYY-MM-DD",
        help="Include only tickets created on or after this date",
    )
    parser.add_argument(
        "--until",
        metavar="YYYY-MM-DD",
        help="Include only tickets created on or before this date",
    )
    parser.add_argument(
        "--graph",
        action="store_true",
        help="Show a terminal line graph of ticket submissions over time "
        "(requires --student or --org)",
    )
    args = parser.parse_args()

    if args.graph and not args.student and not args.org:
        parser.error("--graph requires --student or --org")

    since: date | None = None
    until: date | None = None
    if args.since:
        try:
            since = date.fromisoformat(args.since)
        except ValueError:
            parser.error(f"--since: invalid date '{args.since}' (expected YYYY-MM-DD)")
    if args.until:
        try:
            until = date.fromisoformat(args.until)
        except ValueError:
            parser.error(f"--until: invalid date '{args.until}' (expected YYYY-MM-DD)")

    load_dotenv()

    from src.utils.dns import setup_dns

    setup_dns()

    if args.live:
        tickets = _load_live(project_filter=args.project)
        stats = build_report(_filter_by_date_range(tickets, since, until))
    else:
        tickets = _load_offline(args.input)
        stats = build_report(
            _filter_by_date_range(tickets, since, until), project_filter=args.project
        )

    display_report(
        stats,
        sort_by=args.sort,
        student_filter=args.student,
        org_filter=args.org,
        show_graph=args.graph,
    )


if __name__ == "__main__":
    main()
