#!/usr/bin/env python3
"""Mantis MCP Server — thin adapter over the existing Mantis backend.

2 tools: search_tickets, get_ticket.

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


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
