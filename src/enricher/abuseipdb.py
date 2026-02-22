"""
AbuseIPDB IP lookup.

Returns raw API data for analyst interpretation — no threshold logic applied.
"""

import os
import requests
from rich.console import Console
from rich.table import Table
from rich import box


_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
URL = "https://www.abuseipdb.com/check/{ip}"

console = Console()


def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Query AbuseIPDB for an IP address.

    Returns:
        {
            "score": int,                  # abuse confidence score 0-100
            "total_reports": int,
            "country": str,
            "isp": str,
            "last_reported": str | None,   # ISO timestamp
            "domain": str,
            "usage_type": str,
            "is_tor": bool,
            "raw": dict | None,
            "error": str | None,
        }
    """
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return _error_result("ABUSEIPDB_API_KEY not set")

    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": True}

    try:
        resp = requests.get(_BASE_URL, headers=headers, params=params, timeout=10)
    except requests.RequestException as exc:
        return _error_result(f"Request failed: {exc}")

    if resp.status_code == 401:
        return _error_result("Invalid or missing ABUSEIPDB_API_KEY")

    if not resp.ok:
        return _error_result(f"HTTP {resp.status_code}: {resp.text[:200]}")

    payload = resp.json().get("data", {})
    return {
        "score": payload.get("abuseConfidenceScore", 0),
        "total_reports": payload.get("totalReports", 0),
        "country": payload.get("countryCode", ""),
        "isp": payload.get("isp", ""),
        "last_reported": payload.get("lastReportedAt"),
        "domain": payload.get("domain", ""),
        "usage_type": payload.get("usageType", ""),
        "is_tor": payload.get("isTor", False),
        "raw": payload,
        "error": None,
    }


def display(ip: str, data: dict) -> None:
    """Render a Rich table for AbuseIPDB results."""
    if data.get("error"):
        console.print(f"[dim]AbuseIPDB: {data['error']}[/dim]")
        return

    score = data["score"]
    score_color = "green" if score < 25 else ("yellow" if score < 75 else "red")

    table = Table(title=f"AbuseIPDB — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Confidence Score", f"[{score_color}]{score}%[/{score_color}]")
    table.add_row("Total Reports", str(data["total_reports"]))
    table.add_row("Country", data["country"] or "—")
    table.add_row("ISP", data["isp"] or "—")
    table.add_row("Domain", data["domain"] or "—")
    table.add_row("Usage Type", data["usage_type"] or "—")
    table.add_row("Last Reported", data["last_reported"] or "—")
    if data["is_tor"]:
        table.add_row("Tor Node", "[red]YES[/red]")

    console.print(table)


def _error_result(msg: str) -> dict:
    return {
        "score": 0,
        "total_reports": 0,
        "country": "",
        "isp": "",
        "last_reported": None,
        "domain": "",
        "usage_type": "",
        "is_tor": False,
        "raw": None,
        "error": msg,
    }
