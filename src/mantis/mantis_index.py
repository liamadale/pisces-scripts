#!/usr/bin/env python3
"""
Mantis bulk indexer — fetches all issues from the MantisBT REST API and writes
a local tickets_index.json for fast offline searching.

Usage:
    python src/mantis/mantis_index.py
    python src/mantis/mantis_index.py --max-pages 3   # quick smoke test (~150 tickets)
    python src/mantis/mantis_index.py --output data/tickets/indexed/tickets_index.json
"""

import argparse
import os
import sys
import time

import requests
import urllib3
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.mantis.mantis_search import _normalize_issue
from src.utils.cache import dump_json, load_json
from src.utils.dns import setup_dns

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fetch_all_raw(
    api_url: str,
    api_token: str,
    page_size: int,
    max_pages: int,
    estimated_total: int | None = None,
) -> list[dict]:
    """Phase 1: paginate the MantisBT REST API and collect raw issue dicts."""
    headers = {"Authorization": api_token}
    all_raw: list[dict] = []

    # First request to discover total count
    try:
        resp = requests.get(
            f"{api_url}/api/rest/issues",
            headers=headers,
            params={"page_size": page_size, "page": 1},
            timeout=30,
            verify=False,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        console.print(f"[red]Initial API request failed: {exc}[/red]")
        return []

    data = resp.json()
    issues = data.get("issues", [])

    if not issues:
        console.print(
            "[yellow]API returned no issues on page 1 — nothing to index.[/yellow]"
        )
        return []

    # Determine best total estimate for the progress bar
    total_known = data.get("total_count")  # may be None
    bar_total: int | None = None
    if total_known:
        bar_total = total_known
        console.print(f"[dim]{total_known:,} total tickets reported by API[/dim]")
    elif estimated_total:
        bar_total = estimated_total
        console.print(
            f"[dim]Estimated ~{estimated_total:,} tickets from existing index[/dim]"
        )
    else:
        console.print(
            "[dim]total_count not available — paginating until empty page[/dim]"
        )

    if max_pages:
        bar_total = max_pages * page_size
        console.print(
            f"[dim]Capped at {max_pages} pages (~{bar_total:,} tickets)[/dim]"
        )

    all_raw.extend(issues)

    # Build progress columns — use ticket-count display when we have an estimate,
    # otherwise just show count + spinner (no bar/ETA without a total).
    columns = [
        SpinnerColumn(),
        "[progress.description]{task.description}",
    ]
    if bar_total is not None:
        columns += [
            BarColumn(),
            TextColumn("[cyan]{task.completed:,}/{task.total:,} tickets[/cyan]"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
        ]
    else:
        columns += [
            TextColumn("[cyan]{task.completed:,} tickets[/cyan]"),
            TimeElapsedColumn(),
        ]

    with Progress(*columns, console=console) as progress:
        task = progress.add_task("Fetching...", total=bar_total)
        progress.advance(task, advance=len(issues))

        page = 2
        while True:
            if max_pages and page > max_pages:
                break

            retried = False
            while True:
                try:
                    resp = requests.get(
                        f"{api_url}/api/rest/issues",
                        headers=headers,
                        params={"page_size": page_size, "page": page},
                        timeout=30,
                        verify=False,
                    )
                    resp.raise_for_status()
                    break
                except requests.Timeout:
                    if not retried:
                        retried = True
                        console.print(
                            f"[yellow]Timeout on page {page}, retrying...[/yellow]"
                        )
                        time.sleep(2)
                        continue
                    console.print(f"[red]Page {page} timed out twice — stopping.[/red]")
                    progress.update(task, total=len(all_raw))
                    return all_raw
                except requests.RequestException as exc:
                    console.print(f"[red]Page {page} failed: {exc}[/red]")
                    progress.update(task, total=len(all_raw))
                    return all_raw

            page_issues = resp.json().get("issues", [])
            if not page_issues:
                break

            all_raw.extend(page_issues)
            progress.advance(task, advance=len(page_issues))

            if len(page_issues) < page_size:
                break

            page += 1

        # Snap to exact total now that we know the real count
        progress.update(task, completed=len(all_raw), total=len(all_raw))

    return all_raw


def build_index(
    api_url: str,
    api_token: str,
    page_size: int = 200,
    max_pages: int = 0,
    existing_index_path: str | None = None,
) -> list[dict]:
    """Paginate through the MantisBT REST API and normalize every issue.

    Uses a two-pass approach:
      Phase 1 — fetch all raw issue dicts from the API.
      Phase 2 — build a handler registry (set of all handler user IDs seen
                 across the full corpus), then normalize each issue using that
                 registry so that notes written by *any* known handler are
                 correctly flagged is_admin_note=True.
    """
    # Estimate total from existing index for the progress bar
    estimated_total: int | None = None
    if existing_index_path and os.path.exists(existing_index_path):
        try:
            estimated_total = len(load_json(existing_index_path))  # type: ignore[arg-type]
        except (OSError, ValueError):
            pass

    all_raw = _fetch_all_raw(
        api_url, api_token, page_size, max_pages, estimated_total
    )
    if not all_raw:
        return []

    # Phase 2a: build handler registry from the full corpus
    handler_registry: set[int] = {
        issue["handler"]["id"] for issue in all_raw if issue.get("handler")
    }
    console.print(
        f"[dim]Handler registry: {len(handler_registry)} unique handler IDs[/dim]"
    )

    # Phase 2b: normalize with progress
    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        TextColumn("[cyan]{task.completed:,}/{task.total:,} tickets[/cyan]"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Normalizing...", total=len(all_raw))
        all_tickets: list[dict] = []
        for issue in all_raw:
            all_tickets.append(_normalize_issue(issue, api_url, handler_registry))
            progress.advance(task)

    return all_tickets


def main() -> None:
    """Fetch all Mantis tickets and write a local tickets_index.json."""
    parser = argparse.ArgumentParser(description="PISCES Mantis Bulk Indexer")
    parser.add_argument(
        "--output",
        default=os.path.join(_BASE, "data", "tickets", "indexed", "tickets_index.json"),
        help="Output path for tickets_index.json",
    )
    parser.add_argument("--page-size", type=int, default=200, help="Issues per API page")
    parser.add_argument(
        "--max-pages", type=int, default=0, help="Max pages to fetch (0 = all)"
    )
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    api_token = os.environ.get("MANTIS_API_TOKEN", "")

    if not api_url or not api_token:
        console.print("[red]MANTIS_API_URL and MANTIS_API_TOKEN are required.[/red]")
        sys.exit(1)

    tickets = build_index(
        api_url=api_url,
        api_token=api_token,
        page_size=args.page_size,
        max_pages=args.max_pages,
        existing_index_path=args.output,
    )

    if not tickets:
        console.print("[red]No tickets fetched — aborting write.[/red]")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    tmp_path = args.output + ".tmp"
    dump_json(tickets, tmp_path)
    os.rename(tmp_path, args.output)

    console.print(f"[green]Indexed {len(tickets)} tickets → {args.output}[/green]")


if __name__ == "__main__":
    main()
