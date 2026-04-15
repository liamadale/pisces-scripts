"""
Shodan IP lookup.

Returns open ports, org, country, ISP, OS, hostnames, and known vulns.
"""

import os
import sys

import requests
from rich import box
from rich.console import Console
from rich.table import Table

_BASE_URL = "https://api.shodan.io/shodan/host"
URL = "https://www.shodan.io/search?query={ip}"

console = Console(file=sys.stderr)


def check_ip(ip: str) -> dict:
    """Query Shodan host API for an IP.

    Returns:
        {
            "ports": list[int],
            "org": str,
            "country": str,
            "isp": str,
            "os": str | None,
            "hostnames": list[str],
            "vulns": list[str],
            "raw": dict | None,
            "error": str | None,
        }
    """
    api_key = os.environ.get("SHODAN_API_KEY", "")
    if not api_key:
        return _error_result("SHODAN_API_KEY not set")

    try:
        resp = requests.get(f"{_BASE_URL}/{ip}", params={"key": api_key}, timeout=10)
    except requests.RequestException as exc:
        return _error_result(f"Request failed: {exc}")

    if resp.status_code == 404:
        return _error_result("IP not found in Shodan")

    if resp.status_code == 401:
        return _error_result("Invalid SHODAN_API_KEY")

    if not resp.ok:
        return _error_result(f"HTTP {resp.status_code}: {resp.text[:200]}")

    data = resp.json()
    raw_vulns = data.get("vulns", {})
    vulns = sorted(raw_vulns.keys() if isinstance(raw_vulns, dict) else raw_vulns)
    return {
        "ports": sorted(data.get("ports", [])),
        "org": data.get("org", ""),
        "country": data.get("country_code", ""),
        "isp": data.get("isp", ""),
        "os": data.get("os"),
        "hostnames": data.get("hostnames", []),
        "vulns": vulns,
        "raw": data,
        "error": None,
    }


def display(ip: str, data: dict) -> None:
    """Render a Rich table for Shodan results."""
    if data.get("error"):
        console.print(f"[dim]Shodan: {data['error']}[/dim]")
        return

    table = Table(title=f"Shodan — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Org", data["org"] or "—")
    table.add_row("Country", data["country"] or "—")
    table.add_row("ISP", data["isp"] or "—")
    if data.get("os"):
        table.add_row("OS", data["os"])
    table.add_row("Open Ports", ", ".join(str(p) for p in data["ports"]) or "—")

    hostnames = data["hostnames"][:5]
    table.add_row("Hostnames", ", ".join(hostnames) if hostnames else "—")

    vulns = data["vulns"]
    vuln_str = ", ".join(vulns) if vulns else "—"
    vuln_display = f"[red]{vuln_str}[/red]" if vulns else vuln_str
    table.add_row("Vulns", vuln_display)

    console.print(table)


def _error_result(msg: str) -> dict:
    return {
        "ports": [],
        "org": "",
        "country": "",
        "isp": "",
        "os": None,
        "hostnames": [],
        "vulns": [],
        "raw": None,
        "error": msg,
    }
