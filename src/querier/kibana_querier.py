#!/usr/bin/env python3
"""
PISCES SOC Analyst Tool — Kibana Querier

Thin dispatcher: builds search_params from CLI args, then delegates query
building, display, and interactive loop to KibanaModule / run_kibana_query.

Usage:
    python src/querier/kibana_querier.py --help
    python src/querier/kibana_querier.py --time-range now-24h --severity 2 --cities all --public-only
"""

import argparse
import json
import os
import readline  # noqa: F401 — enables arrow-key history and suppresses escape echoing in input()
import sys

import urllib3
from dotenv import load_dotenv

# The lab Kibana instance uses a self-signed cert; suppress per-request warnings.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from src.querier.filter_loader import load_filters
from src.querier.kibana_module import (
    FILTERS_DIR,
    KibanaModule,
    TIME_RANGES,
    build_query,
    console,
    list_cities,
    run_kibana_query,
)
from src.querier.zeek_modules.base import interactive_loop
from src.utils.banner import BANNER
from src.utils.dns import setup_dns


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PISCES SOC Analyst Tool — Kibana Querier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--time-range",
        default="now-24h",
        help="Kibana date-math time range (default: now-24h). "
        "Available: " + "  ".join(TIME_RANGES),
    )
    parser.add_argument(
        "--severity",
        type=int,
        default=3,
        choices=[1, 2, 3],
        help="Max Suricata severity to include (1=high, 3=low, default: 3)",
    )
    parser.add_argument(
        "--cities",
        default="all",
        help="Comma-separated city/clientID list, or 'all' (default)",
    )
    parser.add_argument(
        "--public-only", action="store_true", help="Exclude private/RFC1918 source IPs"
    )
    parser.add_argument(
        "--signature", help="Filter to alerts matching this signature pattern"
    )
    parser.add_argument("--min-bytes", type=int, help="Minimum bytes_toserver")
    parser.add_argument("--protocol", help="Protocol filter (TCP/UDP/etc.)")
    parser.add_argument(
        "--limit", type=int, default=50, help="Max raw results from ES (default: 50)"
    )
    parser.add_argument(
        "--no-interactive",
        action="store_true",
        help="Print results and exit without the interactive prompt",
    )
    parser.add_argument(
        "--use-cache",
        action="store_true",
        help="Use cached Kibana response if available",
    )
    parser.add_argument(
        "--dump-query",
        action="store_true",
        help="Print the ES query body and exit (for debugging)",
    )
    parser.add_argument(
        "--list-cities",
        action="store_true",
        help="List all clientID values (cities) seen on the ELK stack and exit",
    )
    parser.add_argument(
        "--no-filters",
        action="store_true",
        help="Skip all YAML false positive filters (useful for debugging empty results)",
    )
    args = parser.parse_args()

    console.print(BANNER)

    load_dotenv()
    setup_dns()

    if args.list_cities:
        list_cities()
        return

    search_params = {
        "time_range": args.time_range,
        "severity": args.severity,
        "cities": args.cities,
        "public_only": args.public_only,
        "signature": args.signature,
        "min_bytes": args.min_bytes,
        "protocol": args.protocol,
        "limit": args.limit,
        "no_filters": args.no_filters,
        "use_cache": args.use_cache,
    }

    module = KibanaModule()

    if args.dump_query:
        if args.no_filters:
            must_not: list = []
        else:
            filter_result = load_filters(FILTERS_DIR)
            must_not = filter_result["must_not"]
        cities = None
        if args.cities and args.cities.lower() != "all":
            cities = [c.strip() for c in args.cities.split(",")]
        body, _ = build_query(
            must_not=must_not,
            time_range=args.time_range,
            severity=args.severity,
            cities=cities,
            public_only=args.public_only,
            signature=args.signature,
            min_bytes=args.min_bytes,
            protocol=args.protocol,
            limit=args.limit,
        )
        print(json.dumps(body, indent=2))
        return

    alerts = run_kibana_query(module, search_params)
    if not alerts:
        console.print(
            "[yellow]No alerts returned. Filters may be too aggressive or data may be sparse.[/yellow]"
        )
        return

    module.display(alerts)

    if not args.no_interactive:
        interactive_loop(alerts, search_params, module, query_fn=run_kibana_query)


if __name__ == "__main__":
    main()
