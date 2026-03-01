#!/usr/bin/env python3
"""
Mantis ticket submission — interactive guided flow.

Usage:
    python src/mantis/mantis_submit.py
    # or called programmatically:
    from src.mantis.mantis_submit import submit_interactive
    submit_interactive(alert_dict)
"""

import argparse
import json
import os
import sys
import tempfile
import subprocess

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.utils.dns import setup_dns

console = Console(file=sys.stderr)

# Mantis severity / priority mappings (adjust to local instance config)
SEVERITIES = {
    "1": ("feature", 10),
    "2": ("minor", 20),
    "3": ("major", 30),
    "4": ("crash", 40),
    "5": ("block", 50),
}

PRIORITIES = {
    "1": ("none", 10),
    "2": ("low", 20),
    "3": ("normal", 30),
    "4": ("high", 40),
    "5": ("urgent", 50),
}


def _build_ticket_from_alert(alert: dict) -> dict:
    """Build an initial ticket dict from a Suricata alert."""
    src_ip = alert.get("src_ip", "")
    dest_ip = alert.get("dest_ip", "")
    signature = alert.get("alert", {}).get("signature", "")
    city = alert.get("clientID", "")
    severity = alert.get("alert", {}).get("severity", 2)

    summary = f"[{city.upper()}] {signature} — {src_ip}"
    description = (
        f"**Alert Details**\n\n"
        f"- Source IP: {src_ip}\n"
        f"- Destination IP: {dest_ip}\n"
        f"- Signature: {signature}\n"
        f"- Severity: {severity}\n"
        f"- Municipality: {city}\n"
        f"- Timestamp: {alert.get('@timestamp', '')}\n"
    )
    return {
        "summary": summary,
        "description": description,
        "severity": str(min(severity, 5)),
        "priority": "3",
        "category": "Security Incident",
    }


def prompt_edit_ticket(ticket: dict) -> dict:
    """Let analyst review and edit the ticket fields before submission."""
    console.print("\n[bold yellow]=== Mantis Ticket Submission ===[/bold yellow]")
    console.print(Panel(
        f"Summary:     {ticket['summary']}\n"
        f"Severity:    {ticket['severity']}\n"
        f"Priority:    {ticket['priority']}\n"
        f"Category:    {ticket['category']}",
        title="Ticket Preview",
    ))
    console.print("[dim]Description:[/dim]")
    console.print(ticket["description"])

    choice = input("\nEdit ticket in $EDITOR? [y/N]: ").strip().lower()
    if choice == "y":
        ticket = _edit_in_editor(ticket)

    return ticket


def _edit_in_editor(ticket: dict) -> dict:
    """Open ticket data in $EDITOR as JSON for analyst to modify."""
    editor = os.environ.get("EDITOR", "nano")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json.dump(ticket, tf, indent=2)
        tf_path = tf.name

    subprocess.run([editor, tf_path])

    try:
        with open(tf_path) as fh:
            updated = json.load(fh)
        return updated
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Could not read edited ticket: {exc}[/red]")
        return ticket
    finally:
        os.unlink(tf_path)


def submit_ticket(ticket: dict) -> dict | None:
    """POST ticket to Mantis REST API.

    Returns the created issue response dict, or None on failure.
    """
    api_url = os.environ.get("MANTIS_API_URL", "").rstrip("/")
    api_token = os.environ.get("MANTIS_API_TOKEN", "")

    if not api_url or not api_token:
        console.print("[red]MANTIS_API_URL and MANTIS_API_TOKEN must be set[/red]")
        return None

    headers = {
        "Authorization": api_token,
        "Content-Type": "application/json",
    }

    severity_id = SEVERITIES.get(ticket.get("severity", "3"), ("major", 30))[1]
    priority_id = PRIORITIES.get(ticket.get("priority", "3"), ("normal", 30))[1]

    payload = {
        "summary": ticket.get("summary", ""),
        "description": ticket.get("description", ""),
        "severity": {"id": severity_id},
        "priority": {"id": priority_id},
        "category": {"name": ticket.get("category", "General")},
    }

    try:
        resp = requests.post(
            f"{api_url}/api/rest/issues",
            headers=headers,
            json=payload,
            timeout=15,
            verify=False,
        )
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except requests.RequestException as exc:
        console.print(f"[red]Mantis API request failed: {exc}[/red]")
        return None

    if not resp.ok:
        console.print(f"[red]Mantis API error {resp.status_code}: {resp.text[:300]}[/red]")
        return None

    issue = resp.json().get("issue", {})
    issue_id = issue.get("id", "?")
    console.print(f"[green]Ticket created: #{issue_id}[/green]")
    return issue


def submit_interactive(alert: dict | None = None) -> None:
    """Guide analyst through ticket creation, optionally seeded from an alert."""
    if alert:
        ticket = _build_ticket_from_alert(alert)
    else:
        ticket = {
            "summary": input("Summary: ").strip(),
            "description": "",
            "severity": "3",
            "priority": "3",
            "category": "Security Incident",
        }

    ticket = prompt_edit_ticket(ticket)

    confirm = input("\nSubmit ticket? [y/N]: ").strip().lower()
    if confirm != "y":
        console.print("[yellow]Submission cancelled.[/yellow]")
        return

    submit_ticket(ticket)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Mantis Ticket Submission")
    parser.add_argument("--alert-json", help="Path to alert JSON file to seed ticket")
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    alert = None
    if args.alert_json:
        try:
            with open(args.alert_json) as fh:
                alert = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Could not load alert JSON: {exc}[/red]")
            sys.exit(1)

    submit_interactive(alert)


if __name__ == "__main__":
    main()
