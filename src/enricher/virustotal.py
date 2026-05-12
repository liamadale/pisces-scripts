"""
VirusTotal IP and file-hash lookup.

Provides:
  check_ip()    — last_analysis_stats, country, ASN, AS owner
  check_hash()  — file detection stats, type, size, name, first/last seen
  display()     — Rich table for IP results
  display_hash()— Rich table for hash results
"""

import os
import sys

import requests
from rich import box
from rich.console import Console
from rich.table import Table

_BASE_URL = "https://www.virustotal.com/api/v3/ip_addresses"
_HASH_BASE_URL = "https://www.virustotal.com/api/v3/files"
URL = "https://www.virustotal.com/gui/ip-address/{ip}"
HASH_URL = "https://www.virustotal.com/gui/file/{hash}"

console = Console(file=sys.stderr)

_session = requests.Session()
_session.mount("https://", requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=8))


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
        resp = _session.get(f"{_BASE_URL}/{ip}", headers=headers, timeout=10)
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


def check_hash(hash_value: str) -> dict:
    """Query VirusTotal for a file hash (MD5, SHA1, or SHA256).

    Returns:
        {
            "malicious": int,
            "suspicious": int,
            "harmless": int,
            "undetected": int,
            "file_type": str,
            "size": int | None,
            "name": str,
            "first_seen": str,
            "last_seen": str,
            "raw": dict | None,
            "error": str | None,
        }
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return _hash_error_result("VIRUSTOTAL_API_KEY not set")

    headers = {"x-apikey": api_key}
    try:
        resp = _session.get(f"{_HASH_BASE_URL}/{hash_value}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return _hash_error_result(f"Request failed: {exc}")

    if resp.status_code == 401:
        return _hash_error_result("Invalid VIRUSTOTAL_API_KEY")
    if resp.status_code == 404:
        return _hash_error_result("Hash not found in VirusTotal")
    if not resp.ok:
        return _hash_error_result(f"HTTP {resp.status_code}: {resp.text[:200]}")

    attrs = resp.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    names = attrs.get("names") or []
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "file_type": attrs.get("type_description", ""),
        "size": attrs.get("size"),
        "name": attrs.get("meaningful_name") or (names[0] if names else ""),
        "first_seen": attrs.get("first_submission_date", ""),
        "last_seen": attrs.get("last_analysis_date", ""),
        "raw": attrs,
        "error": None,
    }


def display_hash(hash_value: str, data: dict) -> None:
    """Render a Rich table for VirusTotal file-hash results."""
    if data.get("error"):
        console.print(f"[dim]VirusTotal: {data['error']}[/dim]")
        return

    label = hash_value[:16] + "…" if len(hash_value) > 16 else hash_value
    table = Table(title=f"VirusTotal — {label}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    mal = data["malicious"]
    sus = data["suspicious"]
    table.add_row("Malicious", f"[red]{mal}[/red]" if mal > 0 else str(mal))
    table.add_row("Suspicious", f"[yellow]{sus}[/yellow]" if sus > 0 else str(sus))
    table.add_row("Harmless", str(data["harmless"]))
    table.add_row("Undetected", str(data["undetected"]))
    table.add_row("File Type", data.get("file_type") or "—")
    table.add_row("File Name", data.get("name") or "—")

    size = data.get("size")
    if size is not None:
        for unit in ("B", "KB", "MB", "GB"):
            if size < 1024:
                size_str = f"{size:.0f} {unit}"
                break
            size = size / 1024
        else:
            size_str = f"{size:.1f} TB"
    else:
        size_str = "—"
    table.add_row("Size", size_str)
    table.add_row("First Seen", str(data.get("first_seen")) if data.get("first_seen") else "—")
    table.add_row("Last Seen", str(data.get("last_seen")) if data.get("last_seen") else "—")
    table.add_row("VT Link", HASH_URL.format(hash=hash_value))

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


def _hash_error_result(msg: str) -> dict:
    return {
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "file_type": "",
        "size": None,
        "name": "",
        "first_seen": "",
        "last_seen": "",
        "raw": None,
        "error": msg,
    }
