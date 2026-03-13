#!/usr/bin/env python3
"""
Mantis ticket search — offline index + REST API + web scraping fallback.

Search priority:
  1. Offline: data/tickets/tickets_index.json  (fast, no network)
  2. REST API: GET /api/rest/issues — requires MANTIS_API_TOKEN
  3. Web scraping: login + view_all_bug_page.php — requires PISCES_USERNAME/PASSWORD

Usage:
    python src/mantis/mantis_search.py --query 72.10.3.212
"""

import argparse
import ipaddress
import json
import os
import re
import sys

import requests
import urllib3
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.dns import setup_dns

console = Console(file=sys.stderr)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def sensor_to_project(sensor_val: str) -> str | None:
    """Convert an OpenSearch sensor value to a Mantis project name filter.

    Strips the 'hedgehog-' prefix used by Malcolm sensors.
    Returns None for 'all' or multi-sensor selections (can't map to one project).

    Examples:
        "hedgehog-bonney-lake" → "bonney-lake"
        "all"                  → None
        "hedgehog-a,hedgehog-b"→ None
    """
    if not sensor_val or sensor_val.lower() == "all":
        return None
    sensors = [s.strip() for s in sensor_val.split(",") if s.strip()]
    if len(sensors) != 1:
        return None
    return sensors[0].removeprefix("hedgehog-")

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TICKETS_INDEX = os.path.join(_BASE, "data", "tickets", "tickets_index.json")

# Regex patterns
_IP_RE = re.compile(
    r'\b(\d{1,3})[\.\[\]]+(\d{1,3})[\.\[\]]+(\d{1,3})[\.\[\]]+(\d{1,3})\b'
)
_URL_RE = re.compile(r'https?://[^\s\'"<>]+')

_KIBANA_DOMAINS = {"kibana", "opensearch", "elastic"}
_TI_DOMAINS = {"greynoise", "abuseipdb", "shodan", "virustotal"}


# ---------------------------------------------------------------------------
# Helper: IP extraction
# ---------------------------------------------------------------------------

def _extract_ips(texts: list[str]) -> list[str]:
    """Extract unique public IPs (including defanged like 1.2.3[.]4) from text list."""
    seen: set[str] = set()
    result: list[str] = []
    for text in texts:
        for m in _IP_RE.finditer(text):
            ip_str = f"{m.group(1)}.{m.group(2)}.{m.group(3)}.{m.group(4)}"
            if ip_str in seen:
                continue
            seen.add(ip_str)
            try:
                addr = ipaddress.ip_address(ip_str)
                if not addr.is_private and not addr.is_loopback and not addr.is_reserved:
                    result.append(ip_str)
            except ValueError:
                pass
    return result


# ---------------------------------------------------------------------------
# Helper: link extraction
# ---------------------------------------------------------------------------

def _extract_links(text: str) -> tuple[list[str], list[str]]:
    """Extract URLs from text, classify into (kibana_links, ti_links)."""
    kibana: list[str] = []
    ti: list[str] = []
    for url in _URL_RE.findall(text or ""):
        lower = url.lower()
        if any(d in lower for d in _KIBANA_DOMAINS):
            kibana.append(url)
        elif any(d in lower for d in _TI_DOMAINS):
            ti.append(url)
    return kibana, ti


# ---------------------------------------------------------------------------
# Helper: normalize a raw Mantis API issue dict → standard ticket schema
# ---------------------------------------------------------------------------

def _normalize_issue(issue: dict, api_url: str) -> dict:
    """Convert a raw MantisBT API issue dict to the normalized ticket schema."""
    issue_id = str(issue.get("id", ""))

    handler_raw = issue.get("handler")
    handler = (
        {"id": handler_raw["id"], "name": handler_raw.get("name", "")}
        if handler_raw
        else None
    )
    handler_id = handler_raw["id"] if handler_raw else None

    reporter_raw = issue.get("reporter", {})
    reporter = {"id": reporter_raw.get("id", 0), "name": reporter_raw.get("name", "")}

    notes_raw = issue.get("notes", []) or []
    notes = []
    for n in notes_raw:
        note_reporter_raw = n.get("reporter", {})
        note_reporter = {
            "id": note_reporter_raw.get("id", 0),
            "name": note_reporter_raw.get("name", ""),
        }
        notes.append({
            "id": n.get("id", 0),
            "reporter": note_reporter,
            "text": n.get("text", ""),
            "created_at": n.get("created_at", ""),
            "is_admin_note": handler_id is not None and note_reporter["id"] == handler_id,
        })

    description = issue.get("description", "") or ""
    steps = issue.get("steps_to_reproduce", "") or ""
    additional = issue.get("additional_information", "") or ""

    ips = _extract_ips([
        issue.get("summary", "") or "",
        description,
        steps,
        additional,
        " ".join(n["text"] for n in notes),
    ])

    kibana_links, _ = _extract_links(steps)
    _, ti_links = _extract_links(additional)

    admin_note_count = sum(1 for n in notes if n["is_admin_note"])

    return {
        "id": issue_id,
        "url": f"{api_url}/view.php?id={issue_id}",
        "status": (issue.get("status") or {}).get("name", ""),
        "resolution": (issue.get("resolution") or {}).get("name", ""),
        "severity": (issue.get("severity") or {}).get("name", ""),
        "priority": (issue.get("priority") or {}).get("name", ""),
        "created_at": (issue.get("created_at") or "")[:10],
        "updated_at": (issue.get("updated_at") or "")[:10],
        # Keep last_updated alias for backward compat with existing templates
        "last_updated": (issue.get("updated_at") or "")[:10],
        "project": (issue.get("project") or {}).get("name", ""),
        "category": (issue.get("category") or {}).get("name", ""),
        "reporter": reporter,
        "handler": handler,
        "summary": issue.get("summary", ""),
        "description": description,
        "steps_to_reproduce": steps,
        "additional_information": additional,
        "notes": notes,
        "ips": ips,
        "kibana_links": kibana_links,
        "ti_links": ti_links,
        "note_count": len(notes),
        "admin_note_count": admin_note_count,
    }


# ---------------------------------------------------------------------------
# Offline search
# ---------------------------------------------------------------------------

def _is_ip_query(query: str) -> bool:
    """Return True if query is a valid IPv4 address."""
    try:
        ipaddress.ip_address(query)
        return True
    except ValueError:
        return False


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
    ip_query = _is_ip_query(query)
    results = []
    for ticket in tickets:
        if ip_query:
            # Exact IP match against the pre-extracted ips list — avoids substring
            # false positives like 8.8.8.8 matching 108.8.8.8 or 8.8.8.80
            if query not in ticket.get("ips", []):
                continue
        else:
            if query_lower not in json.dumps(ticket).lower():
                continue
        if city:
            # Check both 'project' (new schema) and 'city' (legacy field) as substring match
            project = ticket.get("project", ticket.get("city", "")).lower()
            if city.lower() not in project:
                continue
        results.append(ticket)
    return results


# ---------------------------------------------------------------------------
# REST API search (primary live method)
# ---------------------------------------------------------------------------

def search_via_api(query: str, city: str | None = None, max_pages: int = 10) -> list[dict]:
    """Fetch issues from MantisBT REST API and filter client-side for query string."""
    api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    api_token = os.environ.get("MANTIS_API_TOKEN", "")

    if not api_url or not api_token:
        return []

    headers = {"Authorization": api_token}
    query_lower = query.lower()
    ip_query = _is_ip_query(query)
    ip_re = re.compile(r'\b' + re.escape(query) + r'\b') if ip_query else None
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
            text = (
                issue.get("summary", "") + " " +
                issue.get("description", "") + " " +
                (issue.get("steps_to_reproduce") or "") + " " +
                (issue.get("additional_information") or "") + " " +
                " ".join(n.get("text", "") for n in issue.get("notes", []))
            )

            if ip_query:
                # Word-boundary match to avoid 8.8.8.8 matching 108.8.8.8 or 8.8.8.80
                if not ip_re.search(text):
                    continue
            else:
                if query_lower not in text.lower():
                    continue

            if city:
                project_name = issue.get("project", {}).get("name", "").lower()
                if city.lower() not in project_name:
                    continue

            results.append(_normalize_issue(issue, api_url))

        total = data.get("total_count") or None
        if total is not None and page * 100 >= total:
            break
        if len(issues) < 100:
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

        issue_id = ""
        ticket_url = ""
        summary = ""
        status = ""
        last_updated = ""

        for cell in cells:
            a = cell.find("a", href=True)
            if a and "view.php?id=" in a.get("href", ""):
                href = a["href"]
                if a.text.strip().isdigit() and not issue_id:
                    issue_id = a.text.strip()
                    ticket_url = href if href.startswith("http") else base_url + "/" + href.lstrip("/")
                elif len(a.text.strip()) > 6:
                    summary = a.text.strip()

        if not issue_id:
            continue

        if query and summary and query.lower() not in summary.lower():
            continue

        text_cells = [c.get_text(strip=True) for c in cells if not c.find("input")]
        status_candidates = [t for t in text_cells if t.lower() in (
            "new", "feedback", "acknowledged", "confirmed", "assigned",
            "resolved", "closed"
        )]
        status = status_candidates[0] if status_candidates else ""
        date_candidates = [t for t in text_cells if re.search(r"\d{4}-\d{2}-\d{2}", t)]
        last_updated = date_candidates[-1][:10] if date_candidates else ""

        results.append({
            "id": issue_id,
            "summary": summary,
            "status": status,
            "last_updated": last_updated,
            "url": ticket_url,
            # Minimal fields for scraping-only results
            "resolution": "",
            "severity": "",
            "priority": "",
            "created_at": "",
            "updated_at": last_updated,
            "project": "",
            "category": "",
            "reporter": {"id": 0, "name": ""},
            "handler": None,
            "description": "",
            "steps_to_reproduce": "",
            "additional_information": "",
            "notes": [],
            "ips": [],
            "kibana_links": [],
            "ti_links": [],
            "note_count": 0,
            "admin_note_count": 0,
        })

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def search(query: str, city: str | None = None) -> list[dict]:
    """Search for tickets matching query.

    Always queries offline index first, then REST API, then web scraping.
    Live API results take precedence over offline results for the same ticket ID.

    Returns:
        Deduplicated list of ticket dicts sorted by ID descending.
    """
    offline = search_offline(query, city)
    offline_by_id = {r["id"]: r for r in offline}

    # Live results override offline for same ID
    live_results: dict[str, dict] = {}
    for r in search_via_api(query, city):
        live_results[r["id"]] = r

    for r in search_via_scraping(query, city):
        if r["id"] not in live_results:
            live_results[r["id"]] = r

    # Merge: live overrides offline
    combined: dict[str, dict] = {**offline_by_id, **live_results}
    results = list(combined.values())
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
    table.add_column("Sev", no_wrap=True)
    table.add_column("Handler", no_wrap=True)
    table.add_column("Notes", no_wrap=True)
    table.add_column("Updated", no_wrap=True)

    for t in results:
        handler_name = t.get("handler", {}) or {}
        handler_str = handler_name.get("name", "—") if isinstance(handler_name, dict) else "—"
        note_count = t.get("note_count", 0)
        admin_count = t.get("admin_note_count", 0)
        notes_str = f"{note_count}" + (f" ({admin_count}★)" if admin_count else "")

        table.add_row(
            t.get("id", ""),
            t.get("summary", ""),
            t.get("status", ""),
            t.get("severity", ""),
            handler_str,
            notes_str,
            t.get("last_updated", "") or t.get("updated_at", ""),
        )

        # Show admin note previews as sub-rows
        for n in t.get("notes", []):
            if n.get("is_admin_note"):
                preview = n["text"][:120].replace("\n", " ")
                table.add_row(
                    "",
                    Text(f"★ {preview}", style="dim"),
                    "", "", "", "", "",
                )

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Mantis Ticket Search")
    parser.add_argument("--query", required=True, help="Search term (IP, keyword, etc.)")
    parser.add_argument("--city", help="Municipality filter")
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    results = search(args.query, city=args.city)
    display_results(results)


if __name__ == "__main__":
    main()
