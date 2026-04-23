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
    python src/mantis/student_activity.py
    python src/mantis/student_activity.py --live
    python src/mantis/student_activity.py --sort tickets
    python src/mantis/student_activity.py --project bonney-lake
    python src/mantis/student_activity.py --student alice
    python src/mantis/student_activity.py --student alice --graph
    python src/mantis/student_activity.py --input data/tickets/indexed/tickets_index.json
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


def display_student_detail(student: StudentStats, show_graph: bool = False) -> None:
    """Render a detailed activity breakdown for a single student."""
    console.print(Rule(f"[cyan]{student.name}[/cyan]"))
    console.print(
        f"  Tickets created: [green]{student.tickets_created}[/green]   "
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


def draw_submission_graph(student: StudentStats) -> None:
    """Render a terminal line graph of ticket submissions over time for one student.

    Granularity is chosen automatically based on the date range:
      - ≤ 5 weeks  → daily
      - ≤ 12 months → weekly (Mon-anchored)
      - > 12 months → monthly

    The graph width is capped to the terminal width minus a small margin so it
    fits comfortably on most screen sizes.
    """
    import plotext as plt

    dated = [
        ref["created_at"]
        for ref in student.created_tickets
        if ref.get("created_at") and len(ref["created_at"]) == 10
    ]
    if not dated:
        console.print("[yellow]No dated tickets — cannot draw graph.[/yellow]")
        return

    parsed = sorted(date.fromisoformat(d) for d in dated)
    span_days = (parsed[-1] - parsed[0]).days

    # Choose bucket granularity
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

    # Build ordered bucket counts
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
    plot_height = 14

    # Show one x-tick label every N buckets so they don't overlap
    tick_step = max(1, len(labels) // (plot_width // 10))
    tick_positions = x_indices[::tick_step]
    tick_labels = labels[::tick_step]

    plt.clf()
    plt.plot_size(plot_width, plot_height)
    plt.theme("dark")
    plt.title(f"Ticket Submissions — {student.name}  ({granularity}ly)")
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


def display_report(
    stats: dict[int, StudentStats],
    sort_by: str = "activity",
    student_filter: str | None = None,
    show_graph: bool = False,
) -> None:
    """Render the student activity report.

    If student_filter matches exactly one student, shows the detail view.
    If it matches multiple, prompts the user to pick one (or show all).
    With no filter, renders the full summary table.
    """
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

    table = Table(
        title=f"Student Activity Report ({len(rows)} students)",
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
        table.add_row(
            s.name,
            str(s.tickets_created),
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
        "--graph",
        action="store_true",
        help="Show a terminal line graph of ticket submissions over time (requires --student)",
    )
    args = parser.parse_args()

    if args.graph and not args.student:
        parser.error("--graph requires --student")

    load_dotenv()

    from src.utils.dns import setup_dns

    setup_dns()

    if args.live:
        tickets = _load_live(project_filter=args.project)
        stats = build_report(tickets)
    else:
        tickets = _load_offline(args.input)
        stats = build_report(tickets, project_filter=args.project)

    display_report(stats, sort_by=args.sort, student_filter=args.student, show_graph=args.graph)


if __name__ == "__main__":
    main()
