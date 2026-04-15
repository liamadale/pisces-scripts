"""
VirusTotal IP lookup.

Returns last_analysis_stats (malicious, suspicious, harmless, undetected),
country, ASN, and AS owner.
"""

import os
import sys

import requests
from rich import box
from rich.console import Console
from rich.table import Table

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
URL = "https://www.virustotal.com/gui/ip-address/{ip}"

console = Console(file=sys.stderr)


def check_ip(ip: str) -> dict:
    """Query VirusTotal for an IP address.

    Returns:
        {
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "country": str,
            "asn": int | None,
            "as_owner": str,
            "raw": dict | None,
            "error": str | None,
        }
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return _error_result("VIRUSTOTAL_API_KEY not set")

    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(f"{_BASE_URL}/{ip}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return _error_result(f"Request failed: {exc}")

    if resp.status_code == 401:
        return _error_result("Invalid VIRUSTOTAL_API_KEY")

    if resp.status_code == 404:
        return _error_result("IP not found in VirusTotal")

    if not resp.ok:
        return _error_result(f"HTTP {resp.status_code}: {resp.text[:200]}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner", ""),
        "raw": attrs,
        "error": None,
    }


def display(ip: str, data: dict) -> None:
    """Render a Rich table for VirusTotal results."""
    if data.get("error"):
        console.print(f"[dim]VirusTotal: {data['error']}[/dim]")
        return

    table = Table(title=f"VirusTotal — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    mal = data["malicious"]
    sus = data["suspicious"]
    table.add_row("Malicious", f"[red]{mal}[/red]" if mal > 0 else str(mal))
    table.add_row("Suspicious", f"[yellow]{sus}[/yellow]" if sus > 0 else str(sus))
    table.add_row("Harmless", str(data["harmless"]))
    table.add_row("Undetected", str(data["undetected"]))
    table.add_row("Country", data["country"] or "—")

    asn = data["asn"]
    as_owner = data["as_owner"]
    asn_str = f"AS{asn} / {as_owner}" if asn else (as_owner or "—")
    table.add_row("ASN / AS Owner", asn_str)

    console.print(table)


def _error_result(msg: str) -> dict:
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "country": "",
        "asn": None,
        "as_owner": "",
        "raw": None,
        "error": msg,
    }
