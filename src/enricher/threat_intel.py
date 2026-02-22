#!/usr/bin/env python3
"""
Threat intelligence enrichment orchestrator.

Pipeline:
  1. GreyNoise  →  benign: offer FP filter, stop
                   malicious: run AbuseIPDB for corroboration
                   not_found: run AbuseIPDB
  2. AbuseIPDB  →  display raw data

Standalone:
    python src/enricher/threat_intel.py --ip 1.2.3.4
"""

import argparse
import os
import sys

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich import box

# Allow running as script from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.enricher import greynoise, abuseipdb
from src.utils.dns import setup_dns

console = Console()


def enrich_ip(ip: str, offer_fp: bool = True) -> dict:
    """Run the full enrichment pipeline for a single IP.

    Args:
        ip: IPv4 or IPv6 address string.
        offer_fp: If True, interactively prompt to create FP filter when GreyNoise
                  classifies the IP as benign.

    Returns:
        {
            "ip": str,
            "greynoise": dict,
            "abuseipdb": dict | None,
        }
    """
    result: dict = {"ip": ip, "greynoise": {}, "abuseipdb": None}

    console.print(f"\n[bold cyan]Enriching {ip}...[/bold cyan]")

    # ---- Step 1: GreyNoise ----
    gn = greynoise.check_ip(ip)
    result["greynoise"] = gn
    classification = gn["classification"]

    _display_greynoise(ip, gn)

    if classification == "benign":
        if offer_fp:
            add_fp = input("\nGreyNoise classifies this as benign. Add FP filter? [y/N]: ").strip().lower()
            if add_fp == "y":
                # Lazy import to avoid circular dependency when called from querier
                from src.querier.fp_manager import create_filter_interactive
                create_filter_interactive(alert={"src_ip": ip})
        return result

    # ---- Step 2: AbuseIPDB ----
    if classification == "malicious":
        console.print("[yellow]GreyNoise: malicious — querying AbuseIPDB for corroboration...[/yellow]")
    else:
        console.print("[dim]GreyNoise: not in dataset — querying AbuseIPDB...[/dim]")

    ab = abuseipdb.check_ip(ip)
    result["abuseipdb"] = ab
    _display_abuseipdb(ip, ab)

    return result


def _display_greynoise(ip: str, gn: dict) -> None:
    classification = gn["classification"]
    color = {"benign": "green", "malicious": "red"}.get(classification, "yellow")

    table = Table(title=f"GreyNoise — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Classification", f"[{color}]{classification}[/{color}]")
    if gn.get("name"):
        table.add_row("Name", gn["name"])
    if gn.get("reason"):
        table.add_row("Reason", gn["reason"])

    console.print(table)


def _display_abuseipdb(ip: str, ab: dict) -> None:
    if ab.get("error"):
        console.print(f"[red]AbuseIPDB error: {ab['error']}[/red]")
        return

    score = ab["score"]
    score_color = "green" if score < 25 else ("yellow" if score < 75 else "red")

    table = Table(title=f"AbuseIPDB — {ip}", box=box.SIMPLE)
    table.add_column("Field", style="cyan")
    table.add_column("Value")

    table.add_row("Confidence Score", f"[{score_color}]{score}%[/{score_color}]")
    table.add_row("Total Reports", str(ab["total_reports"]))
    table.add_row("Country", ab["country"] or "—")
    table.add_row("ISP", ab["isp"] or "—")
    table.add_row("Domain", ab["domain"] or "—")
    table.add_row("Usage Type", ab["usage_type"] or "—")
    table.add_row("Last Reported", ab["last_reported"] or "—")
    if ab["is_tor"]:
        table.add_row("Tor Node", "[red]YES[/red]")

    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Threat Intel Enrichment")
    parser.add_argument("--ip", required=True, help="IP address to enrich")
    parser.add_argument("--no-fp", action="store_true", help="Skip FP filter offer")
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    enrich_ip(args.ip, offer_fp=not args.no_fp)


if __name__ == "__main__":
    main()
