"""
GreyNoise IP lookup.

Returns classification: benign | malicious | not_found
"""

import os
import sys

import requests
from rich import box
from rich.console import Console
from rich.table import Table

_BASE_URL = "https://api.greynoise.io/v3/community"
URL = "https://viz.greynoise.io/ip/{ip}"

console = Console(file=sys.stderr)


def check_ip(ip: str) -> dict:
    """Query GreyNoise community API for an IP.

    Returns:
        {
            "classification": "benign" | "malicious" | "not_found",
            "name": str,
            "reason": str,
            "raw": dict | None,
        }
    """
    api_key = os.environ.get("GREYNOISE_API_KEY", "")
    headers = {"key": api_key} if api_key else {}

    try:
        resp = requests.get(f"{_BASE_URL}/{ip}", headers=headers, timeout=10)
    except requests.RequestException as exc:
        return {
            "classification": "not_found",
            "name": "",
            "reason": f"Request failed: {exc}",
            "raw": None,
        }

    if resp.status_code == 404:
        return {
            "classification": "not_found",
            "name": "",
            "reason": "IP not in GreyNoise dataset",
            "raw": None,
        }

    if resp.status_code == 401:
        return {
            "classification": "not_found",
            "name": "",
            "reason": "Invalid or missing GREYNOISE_API_KEY",
            "raw": None,
        }

    if not resp.ok:
        return {
            "classification": "not_found",
            "name": "",
            "reason": f"HTTP {resp.status_code}",
            "raw": None,
        }

    data = resp.json()
    classification = data.get("classification", "not_found")
    return {
        "classification": classification,
        "name": data.get("name", ""),
        "reason": data.get("message", ""),
        "raw": data,
    }


def display(ip: str, data: dict) -> None:
    """Render a Rich table for GreyNoise results."""
    classification = data["classification"]
    color = {"benign": "green", "malicious": "red"}.get(classification, "yellow")

    table = Table(title=f"GreyNoise — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Classification", f"[{color}]{classification}[/{color}]")
    if data.get("name"):
        table.add_row("Name", data["name"])
    if data.get("reason"):
        table.add_row("Reason", data["reason"])

    console.print(table)
