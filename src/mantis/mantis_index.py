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
import json
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
    TaskProgressColumn,
    TimeElapsedColumn,
)

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.mantis.mantis_search import _normalize_issue
from src.utils.dns import setup_dns

console = Console()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _fetch_all_raw(
    api_url: str,
    api_token: str,
    page_size: int,
    max_pages: int,
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

    # total_count is present but None on this Mantis instance; paginate until empty
    total_known = data.get("total_count")  # may be None
    total_pages_est: int | None = None
    if total_known:
        total_pages_est = (total_known + page_size - 1) // page_size
        console.print(
            f"[dim]{total_known} total tickets reported, ~{total_pages_est} pages[/dim]"
        )
    else:
        console.print(
            "[dim]total_count not available — paginating until empty page[/dim]"
        )

    all_raw.extend(issues)

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        total_for_bar: int | None = total_pages_est if total_known else None
        if max_pages:
            total_for_bar = max_pages
            console.print(
                f"[dim]Capped at {max_pages} pages ({max_pages * page_size} tickets)[/dim]"
            )

        task = progress.add_task("Fetching tickets...", total=total_for_bar)
        progress.advance(task)  # page 1 already done

        page = 2
        while True:
            if max_pages and page > max_pages:
                break

            time.sleep(0.1)
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
                    return all_raw
                except requests.RequestException as exc:
                    console.print(f"[red]Page {page} failed: {exc}[/red]")
                    return all_raw

            page_issues = resp.json().get("issues", [])
            if not page_issues:
                break

            all_raw.extend(page_issues)
            progress.advance(task)

            if len(page_issues) < page_size:
                break

            page += 1

    return all_raw


def build_index(
    api_url: str,
    api_token: str,
    page_size: int = 50,
    max_pages: int = 0,
) -> list[dict]:
    """Paginate through the MantisBT REST API and normalize every issue.

    Uses a two-pass approach:
      Phase 1 — fetch all raw issue dicts from the API.
      Phase 2 — build a handler registry (set of all handler user IDs seen
                 across the full corpus), then normalize each issue using that
                 registry so that notes written by *any* known handler are
                 correctly flagged is_admin_note=True.
    """
    all_raw = _fetch_all_raw(api_url, api_token, page_size, max_pages)
    if not all_raw:
        return []

    # Phase 2a: build handler registry from the full corpus
    handler_registry: set[int] = {
        issue["handler"]["id"] for issue in all_raw if issue.get("handler")
    }
    console.print(
        f"[dim]Handler registry: {len(handler_registry)} unique handler IDs[/dim]"
    )

    # Phase 2b: normalize with registry
    all_tickets = [
        _normalize_issue(issue, api_url, handler_registry) for issue in all_raw
    ]
    return all_tickets


def main() -> None:
    """Fetch all Mantis tickets and write a local tickets_index.json."""
    parser = argparse.ArgumentParser(description="PISCES Mantis Bulk Indexer")
    parser.add_argument(
        "--output",
        default=os.path.join(_BASE, "data", "tickets", "indexed", "tickets_index.json"),
        help="Output path for tickets_index.json",
    )
    parser.add_argument("--page-size", type=int, default=50, help="Issues per API page")
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
    )

    if not tickets:
        console.print("[red]No tickets fetched — aborting write.[/red]")
        sys.exit(1)

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    tmp_path = args.output + ".tmp"
    with open(tmp_path, "w") as fh:
        json.dump(tickets, fh, indent=2)
    os.rename(tmp_path, args.output)

    console.print(f"[green]Indexed {len(tickets)} tickets → {args.output}[/green]")


if __name__ == "__main__":
    main()
