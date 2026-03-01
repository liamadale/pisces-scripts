#!/usr/bin/env python3
"""Mantis MCP Server — thin adapter over the existing Mantis backend.

4 tools: search_tickets, get_ticket, create_ticket, create_ticket_from_alert.

Run locally (MCP Inspector):
    source .venv/bin/activate && pip install mcp[cli]
    MANTIS_API_URL=https://mantis.local MANTIS_API_TOKEN=tok mcp dev mcp/mantis/server.py

Run via Docker:
    docker build -f mcp/mantis/Dockerfile -t mantis-mcp .
    docker run --rm -i -e MANTIS_API_URL -e MANTIS_API_TOKEN mantis-mcp
"""

import json
import sys
import os
from typing import Optional

# Allow importing project modules when run from mcp/mantis/ or as a Docker container.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dotenv import load_dotenv

_env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(os.path.abspath(_env_path))

from src.utils.dns import setup_dns
setup_dns()

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from mcp.server.fastmcp import FastMCP

from src.mantis.mantis_search import search
from src.mantis.mantis_submit import submit_ticket, _build_ticket_from_alert, SEVERITIES, PRIORITIES

mcp = FastMCP("mantis")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ok(data) -> str:
    return json.dumps({"status": "ok", "data": data}, default=str)


def _err(msg: str) -> str:
    return json.dumps({"status": "error", "message": msg})


def _mantis_session() -> requests.Session:
    """Return a requests Session with the Mantis Bearer token pre-configured."""
    session = requests.Session()
    token = os.environ.get("MANTIS_API_TOKEN", "")
    if token:
        session.headers["Authorization"] = token
    return session


# Reverse mappings: severity/priority name → numeric string key used by submit_ticket
_SEVERITY_NAME_TO_KEY = {name: key for key, (name, _id) in SEVERITIES.items()}
_PRIORITY_NAME_TO_KEY = {name: key for key, (name, _id) in PRIORITIES.items()}


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def search_tickets(
    query: str,
    city: Optional[str] = None,
    live: bool = False,
) -> str:
    """Search MantisBT tickets for an IP address, keyword, or phrase.

    Args:
        query: IP address, keyword, or phrase to search for.
        city: Optional municipality/project name filter.
        live: If True, also query the REST API and scrape the web UI for full-text
              results (slower, requires network access to MantisBT). If False, only
              the local offline ticket index is searched (fast, no network).

    Returns a deduplicated list of ticket dicts sorted by ID descending.
    Each ticket has: id, summary, status, last_updated, url.
    """
    try:
        results = search(query, city=city, live=live)
        return _ok({"count": len(results), "tickets": results})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def get_ticket(ticket_id: int) -> str:
    """Fetch a single MantisBT issue by numeric ID via the REST API.

    Returns the full issue dict including summary, description, notes, status,
    severity, priority, reporter, and timestamps.

    Args:
        ticket_id: Numeric MantisBT issue ID.
    """
    try:
        api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
        if not api_url:
            return _err("MANTIS_API_URL is not set")

        session = _mantis_session()
        resp = session.get(
            f"{api_url}/api/rest/issues/{ticket_id}",
            timeout=15,
            verify=False,
        )

        if resp.status_code == 401:
            return _err("Mantis API auth failed — check MANTIS_API_TOKEN")
        if resp.status_code == 404:
            return _err(f"Ticket #{ticket_id} not found")
        if not resp.ok:
            return _err(f"Mantis API error {resp.status_code}: {resp.text[:300]}")

        issue = resp.json().get("issues", [{}])[0]
        return _ok(issue)
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def create_ticket(
    summary: str,
    description: str,
    severity: str = "major",
    priority: str = "normal",
    category: str = "General",
) -> str:
    """Create a new MantisBT ticket via the REST API.

    Args:
        summary: Short one-line ticket title.
        description: Full ticket body / description text.
        severity: Severity level — one of: feature, minor, major, crash, block.
        priority: Priority level — one of: none, low, normal, high, urgent.
        category: MantisBT category name (default "General").

    Returns {ticket_id, url} on success.
    """
    try:
        sev_key = _SEVERITY_NAME_TO_KEY.get(severity)
        if sev_key is None:
            valid = ", ".join(_SEVERITY_NAME_TO_KEY)
            return _err(f"Invalid severity '{severity}'. Valid values: {valid}")

        pri_key = _PRIORITY_NAME_TO_KEY.get(priority)
        if pri_key is None:
            valid = ", ".join(_PRIORITY_NAME_TO_KEY)
            return _err(f"Invalid priority '{priority}'. Valid values: {valid}")

        ticket = {
            "summary": summary,
            "description": description,
            "severity": sev_key,
            "priority": pri_key,
            "category": category,
        }
        issue = submit_ticket(ticket)
        if issue is None:
            return _err("Ticket submission failed — check MANTIS_API_URL and MANTIS_API_TOKEN")

        api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
        issue_id = issue.get("id", "?")
        return _ok({
            "ticket_id": issue_id,
            "url": f"{api_url}/view.php?id={issue_id}",
        })
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def create_ticket_from_alert(
    alert_json: str,
    severity: Optional[str] = None,
    priority: Optional[str] = None,
) -> str:
    """Create a MantisBT ticket pre-filled from a Suricata alert dict.

    The alert JSON should match the structure used by the PISCES alert pipeline.
    Required keys: src_ip, dest_ip, alert.signature, alert.severity, clientID.

    Args:
        alert_json: JSON string of the alert dict.
        severity: Override severity — one of: feature, minor, major, crash, block.
                  If omitted, derived from alert.severity field.
        priority: Override priority — one of: none, low, normal, high, urgent.
                  If omitted, defaults to normal.

    Returns {ticket_id, url} on success.
    """
    try:
        try:
            alert = json.loads(alert_json)
        except json.JSONDecodeError as exc:
            return _err(f"Invalid JSON in alert_json: {exc}")

        ticket = _build_ticket_from_alert(alert)

        if severity is not None:
            sev_key = _SEVERITY_NAME_TO_KEY.get(severity)
            if sev_key is None:
                valid = ", ".join(_SEVERITY_NAME_TO_KEY)
                return _err(f"Invalid severity '{severity}'. Valid values: {valid}")
            ticket["severity"] = sev_key

        if priority is not None:
            pri_key = _PRIORITY_NAME_TO_KEY.get(priority)
            if pri_key is None:
                valid = ", ".join(_PRIORITY_NAME_TO_KEY)
                return _err(f"Invalid priority '{priority}'. Valid values: {valid}")
            ticket["priority"] = pri_key

        issue = submit_ticket(ticket)
        if issue is None:
            return _err("Ticket submission failed — check MANTIS_API_URL and MANTIS_API_TOKEN")

        api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
        issue_id = issue.get("id", "?")
        return _ok({
            "ticket_id": issue_id,
            "url": f"{api_url}/view.php?id={issue_id}",
        })
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
