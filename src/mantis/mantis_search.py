#!/usr/bin/env python3
"""
Mantis ticket search — offline index + REST API + web scraping fallback.

Search priority:
  1. Offline: data/tickets/tickets_index.json  (fast, no network)
  2. REST API: GET /api/rest/issues — requires MANTIS_API_TOKEN
  3. Web scraping: login + view_all_bug_page.php — requires PISCES_USERNAME/PASSWORD

Usage:
    python src/mantis/mantis_search.py --query 72.10.3.212
    python src/mantis/mantis_search.py --query "STREAM anomaly" --live
"""

import argparse
import json
import os
import sys

import requests
import urllib3
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.dns import setup_dns

console = Console(file=sys.stderr)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TICKETS_INDEX = os.path.join(_BASE, "data", "tickets", "tickets_index.json")


# ---------------------------------------------------------------------------
# Offline search
# ---------------------------------------------------------------------------

def search_offline(query: str, city: str | None = None) -> list[dict]:
    """Search the local tickets_index.json for query string."""
    if not os.path.exists(TICKETS_INDEX):
        return []
    try:
        with open(TICKETS_INDEX) as fh:
            tickets: list[dict] = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    query_lower = query.lower()
    results = []
    for ticket in tickets:
        if query_lower not in json.dumps(ticket).lower():
            continue
        if city and ticket.get("city", "").lower() != city.lower():
            continue
        results.append(ticket)
    return results


# ---------------------------------------------------------------------------
# REST API search (primary live method)
# ---------------------------------------------------------------------------

def search_via_api(query: str, city: str | None = None, max_pages: int = 10) -> list[dict]:
    """Fetch issues from MantisBT REST API and filter client-side for query string.

    Fetches up to max_pages * 100 recent issues and returns those whose summary
    or description contain the query text.
    """
    api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    api_token = os.environ.get("MANTIS_API_TOKEN", "")

    if not api_url or not api_token:
        return []

    headers = {"Authorization": api_token}
    query_lower = query.lower()
    results = []

    console.print(f"[dim]Querying Mantis REST API for '{query}'...[/dim]")

    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(
                f"{api_url}/api/rest/issues",
                headers=headers,
                params={"page_size": 100, "page": page},
                timeout=20,
                verify=False,
            )
        except requests.RequestException as exc:
            console.print(f"[red]Mantis API request failed: {exc}[/red]")
            break

        if resp.status_code == 401:
            console.print("[red]Mantis API auth failed — check MANTIS_API_TOKEN[/red]")
            break

        if not resp.ok:
            console.print(f"[red]Mantis API error {resp.status_code}[/red]")
            break

        data = resp.json()
        issues = data.get("issues", [])
        if not issues:
            break

        for issue in issues:
            # Search in summary + description
            text = (
                issue.get("summary", "") + " " +
                issue.get("description", "") + " " +
                " ".join(n.get("text", "") for n in issue.get("notes", []))
            ).lower()

            if query_lower not in text:
                continue

            if city:
                project_name = issue.get("project", {}).get("name", "").lower()
                if city.lower() not in project_name:
                    continue

            issue_id = str(issue.get("id", ""))
            results.append({
                "id": issue_id,
                "summary": issue.get("summary", ""),
                "status": issue.get("status", {}).get("name", ""),
                "last_updated": issue.get("updated_at", "")[:10] if issue.get("updated_at") else "",
                "url": f"{api_url}/view.php?id={issue_id}",
            })

        # Stop if this was the last page
        total = data.get("total_count", len(issues))
        if page * 100 >= total:
            break

    return results


# ---------------------------------------------------------------------------
# Web scraping fallback
# ---------------------------------------------------------------------------

def search_via_scraping(query: str, city: str | None = None) -> list[dict]:
    """Log in to MantisBT and scrape view_all_bug_page.php search results."""
    from bs4 import BeautifulSoup

    mantis_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    username = os.environ.get("PISCES_USERNAME", "")
    password = os.environ.get("PISCES_PASSWORD", "")

    if not all([mantis_url, username, password]):
        console.print(
            "[yellow]Web scraping requires MANTIS_API_URL, PISCES_USERNAME, "
            "PISCES_PASSWORD[/yellow]"
        )
        return []

    session = requests.Session()

    # Login
    try:
        resp = session.post(
            f"{mantis_url}/login.php",
            data={"username": username, "password": password, "return": "index.php"},
            timeout=15,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        console.print(f"[red]Mantis login failed: {exc}[/red]")
        return []

    if "login.php" in resp.url:
        console.print("[red]Mantis authentication failed — check credentials[/red]")
        return []

    # Search via view_all_bug_page.php
    try:
        resp = session.get(
            f"{mantis_url}/view_all_bug_page.php",
            params={"search": query, "type": "1", "project_id": "0"},
            timeout=15,
            verify=False,
        )
    except requests.RequestException as exc:
        console.print(f"[red]Mantis search request failed: {exc}[/red]")
        return []

    return _parse_scrape_results(resp.text, base_url=mantis_url, query=query)


def _parse_scrape_results(html: str, base_url: str, query: str = "") -> list[dict]:
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    results = []

    for row in soup.select("tr.row-1, tr.row-2"):
        cells = row.find_all("td")
        if len(cells) < 5:
            continue

        # MantisBT column layout (default view):
        #  0: checkbox  1: ID  2: project  3: category  4: severity
        #  5: status    6: updated  7: summary (with link)
        # Find the ID cell — it contains a link to view.php?id=N
        issue_id = ""
        ticket_url = ""
        summary = ""
        status = ""
        last_updated = ""

        for cell in cells:
            a = cell.find("a", href=True)
            if a and "view.php?id=" in a.get("href", ""):
                href = a["href"]
                # ID cell: short numeric text
                if a.text.strip().isdigit() and not issue_id:
                    issue_id = a.text.strip()
                    ticket_url = href if href.startswith("http") else base_url + "/" + href.lstrip("/")
                # Summary cell: longer descriptive text
                elif len(a.text.strip()) > 6:
                    summary = a.text.strip()

        if not issue_id:
            continue

        # Guard against view_all_bug_page returning an unfiltered default view:
        # require the query to appear in the summary if we have one.
        if query and summary and query.lower() not in summary.lower():
            continue

        # Pull status and last-updated from their cells by position
        # (positions vary by MantisBT config, so grab non-link text cells)
        text_cells = [c.get_text(strip=True) for c in cells if not c.find("input")]
        # status is usually a short word like "new", "resolved", "acknowledged"
        status_candidates = [t for t in text_cells if t.lower() in (
            "new", "feedback", "acknowledged", "confirmed", "assigned",
            "resolved", "closed"
        )]
        status = status_candidates[0] if status_candidates else ""
        # last updated: look for date-like strings (YYYY-MM-DD or similar)
        import re
        date_candidates = [t for t in text_cells if re.search(r"\d{4}-\d{2}-\d{2}", t)]
        last_updated = date_candidates[-1][:10] if date_candidates else ""

        results.append({
            "id": issue_id,
            "summary": summary,
            "status": status,
            "last_updated": last_updated,
            "url": ticket_url,
        })

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def search(query: str, city: str | None = None, live: bool = False) -> list[dict]:
    """Search for tickets matching query.

    Args:
        query: IP address, keyword, or phrase to search for.
        city:  Optional municipality filter.
        live:  If True, query both the REST API (summaries) AND web scraping
               (full-text including descriptions/notes) and merge results.
               REST API alone misses IPs that only appear in ticket bodies.

    Returns:
        Deduplicated list of ticket dicts sorted by ID descending.
    """
    results = search_offline(query, city)
    seen = {r["id"] for r in results}

    if live:
        # Run both — REST API searches summaries only; scraping does full-text
        for r in search_via_api(query, city):
            if r["id"] not in seen:
                results.append(r)
                seen.add(r["id"])

        for r in search_via_scraping(query, city):
            if r["id"] not in seen:
                results.append(r)
                seen.add(r["id"])

    # Sort by ID descending (newest first)
    results.sort(key=lambda r: int(r["id"]) if r["id"].isdigit() else 0, reverse=True)
    return results


def display_results(results: list[dict]) -> None:
    if not results:
        console.print("[yellow]No tickets found.[/yellow]")
        return

    table = Table(title=f"Mantis Tickets ({len(results)} found)", box=box.SIMPLE)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Summary", ratio=2)
    table.add_column("Status", style="green", no_wrap=True)
    table.add_column("Updated", no_wrap=True)
    table.add_column("URL", style="dim")

    for t in results:
        table.add_row(
            t.get("id", ""),
            t.get("summary", ""),
            t.get("status", ""),
            t.get("last_updated", ""),
            t.get("url", ""),
        )

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Mantis Ticket Search")
    parser.add_argument("--query", required=True, help="Search term (IP, keyword, etc.)")
    parser.add_argument("--city", help="Municipality filter")
    parser.add_argument("--live", action="store_true",
                        help="Query live Mantis (REST API + scraping fallback)")
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    results = search(args.query, city=args.city, live=args.live)
    display_results(results)


if __name__ == "__main__":
    main()
