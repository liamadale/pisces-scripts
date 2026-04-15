#!/usr/bin/env python3
"""
Threat intelligence enrichment orchestrator.

Pipeline:
  1. GreyNoise  →  benign: offer FP filter, fall through to URL block
                   malicious/not_found: continue
  2. AbuseIPDB  →  display raw data
  3. Shodan     →  display ports, vulns, org
  4. VirusTotal →  display detection stats
  5. URLs       →  always printed

Standalone:
    python src/enricher/threat_intel.py --ip 1.2.3.4
"""

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table

# Allow running as script from project root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.enricher import abuseipdb, greynoise, shodan, virustotal
from src.utils.dns import setup_dns

console = Console(file=sys.stderr)


def enrich_ip(ip: str, offer_fp: bool = True, urls_only: bool = False) -> dict:
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
            "shodan": dict | None,
            "virustotal": dict | None,
        }
    """
    result: dict = {
        "ip": ip,
        "greynoise": {},
        "abuseipdb": None,
        "shodan": None,
        "virustotal": None,
    }

    if urls_only:
        _display_urls(ip)
        return result

    console.print(f"\n[bold cyan]Enriching {ip}...[/bold cyan]")

    # ---- Step 1: GreyNoise ----
    gn = greynoise.check_ip(ip)
    result["greynoise"] = gn
    classification = gn["classification"]

    greynoise.display(ip, gn)

    if classification == "benign":
        if offer_fp:
            add_fp = (
                input("\nGreyNoise classifies this as benign. Add FP filter? [y/N]: ")
                .strip()
                .lower()
            )
            if add_fp == "y":
                # Lazy import to avoid circular dependency when called from querier
                from src.querier.fp_manager import create_filter_interactive

                name = gn.get("name", "")
                hint = f"{name} — GreyNoise benign" if name else ""
                create_filter_interactive(alert={"src_ip": ip}, comment_hint=hint)
        _display_urls(ip)
        return result

    if classification == "malicious":
        console.print(
            "[yellow]GreyNoise: malicious — querying AbuseIPDB for corroboration...[/yellow]\n"
        )
    else:
        console.print("[dim]GreyNoise: not in dataset — querying AbuseIPDB...[/dim]\n")

    # ---- Steps 2-4: AbuseIPDB, Shodan, VirusTotal in parallel ----
    remaining = {
        "abuseipdb": abuseipdb.check_ip,
        "shodan": shodan.check_ip,
        "virustotal": virustotal.check_ip,
    }
    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {pool.submit(fn, ip): name for name, fn in remaining.items()}
        for future in as_completed(futures):
            result[futures[future]] = future.result()

    # Display in canonical order
    abuseipdb.display(ip, result["abuseipdb"])
    shodan.display(ip, result["shodan"])
    virustotal.display(ip, result["virustotal"])

    # ---- Step 5: Reference URLs (always) ----
    _display_urls(ip)

    return result


def _display_urls(ip: str) -> None:
    """Print reference links for all enrichment services."""
    table = Table(title="Reference Links", box=None, show_header=False, padding=(0, 2))
    table.add_column("Service", style="dim")
    table.add_column("URL", style="blue")

    services = [
        ("GreyNoise", greynoise.URL),
        ("AbuseIPDB", abuseipdb.URL),
        ("Shodan", shodan.URL),
        ("VirusTotal", virustotal.URL),
    ]
    for name, url_template in services:
        table.add_row(name, url_template.format(ip=ip))

    console.print()
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(description="PISCES Threat Intel Enrichment")
    parser.add_argument("--ip", required=True, help="IP address to enrich")
    parser.add_argument("--no-fp", action="store_true", help="Skip FP filter offer")
    parser.add_argument(
        "--urls-only",
        action="store_true",
        help="Print reference URLs without making any API calls",
    )
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    enrich_ip(args.ip, offer_fp=not args.no_fp, urls_only=args.urls_only)


if __name__ == "__main__":
    main()
