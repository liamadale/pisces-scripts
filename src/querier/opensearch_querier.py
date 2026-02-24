#!/usr/bin/env python3
"""
PISCES SOC Analyst Tool — OpenSearch / Malcolm / Zeek Querier

Thin dispatcher: pre-parses --log-type, loads the matching protocol module,
then delegates query building, display, and interactive loop to that module.

Usage:
    python src/querier/opensearch_querier.py --help
    python src/querier/opensearch_querier.py --log-type conn --public-only
    python src/querier/opensearch_querier.py --log-type dns --rcode NXDOMAIN
    python src/querier/opensearch_querier.py --log-type notice
    python src/querier/opensearch_querier.py --log-type ssh --failed-only
"""

import argparse
import json
import os
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import (
    TIME_RANGES,
    build_base_query,
    console,
    interactive_loop,
    list_indices,
    list_log_types,
    list_sensors,
    load_with_remap,
    match_all_sample,
    query_opensearch,
    run_query,
    FILTERS_DIR,
)
from src.utils.banner import BANNER
from src.utils.dns import setup_dns

_VALID_LOG_TYPES = list(MODULES.keys())


def _build_parser(module) -> argparse.ArgumentParser:
    """Build the full argument parser: shared args + module-specific args."""
    parser = argparse.ArgumentParser(
        description="PISCES SOC Analyst Tool — OpenSearch / Malcolm / Zeek Querier",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Shared args
    parser.add_argument(
        "--time-range", default="now-24h",
        help="Date-math time range (default: now-24h). Available: " + "  ".join(TIME_RANGES),
    )
    parser.add_argument(
        "--sensor", default="all",
        help="Comma-separated host.name list, or 'all' (default)",
    )
    parser.add_argument(
        "--log-type", default="conn",
        choices=_VALID_LOG_TYPES,
        help="Zeek log type to query (default: conn). Options: " + ", ".join(_VALID_LOG_TYPES),
    )
    parser.add_argument(
        "--limit", type=int, default=50,
        help="Max raw results from OpenSearch (default: 50)",
    )
    parser.add_argument(
        "--public-only", action="store_true",
        help="Exclude private/RFC1918 source IPs",
    )
    parser.add_argument(
        "--src-ip",
        help="Filter to a specific source IP",
    )
    parser.add_argument(
        "--direction",
        help=(
            "Filter by network.direction "
            "(e.g. inbound, outbound, internal, external, ingress, egress)"
        ),
    )
    parser.add_argument(
        "--no-filters", action="store_true",
        help="Skip all YAML false positive filters (useful for debugging empty results)",
    )
    parser.add_argument(
        "--no-interactive", action="store_true",
        help="Print results and exit without the interactive prompt",
    )
    parser.add_argument(
        "--list-sensors", action="store_true",
        help="Aggregate on host.name and exit",
    )
    parser.add_argument(
        "--list-log-types", action="store_true",
        help="Aggregate on event.dataset and exit",
    )
    parser.add_argument(
        "--list-indices", action="store_true",
        help="List all indices in the cluster and exit (for debugging)",
    )
    parser.add_argument(
        "--match-all-sample", action="store_true",
        help="Run a plain match_all and print raw hits (shows actual field names)",
    )
    parser.add_argument(
        "--dump-query", action="store_true",
        help="Print the ES query body and exit (for debugging)",
    )
    parser.add_argument(
        "--use-cache", action="store_true",
        help="Use cached OpenSearch response if available",
    )

    # Protocol-specific args from the module
    module.add_args(parser)

    return parser


def main() -> None:
    # 1. Pre-parse --log-type so we can load the module before building the full parser.
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--log-type", default="conn")
    known, _ = pre.parse_known_args()
    log_type = known.log_type if known.log_type in MODULES else "conn"

    # 2. Load module
    module = MODULES[log_type]

    # 3. Build full parser with module-specific args and parse
    parser = _build_parser(module)
    args = parser.parse_args()

    console.print(BANNER)

    load_dotenv()
    setup_dns()

    # 4. Diagnostic / listing commands — run and exit
    if args.list_indices:
        list_indices()
        return

    if args.match_all_sample:
        match_all_sample(args.time_range)
        return

    if args.list_sensors:
        list_sensors(args.time_range)
        return

    if args.list_log_types:
        list_log_types(args.time_range)
        return

    # 5. Build search_params from all parsed args (shared + module-specific)
    search_params = vars(args)

    # 6. --dump-query: build the query body and print without executing
    if args.dump_query:
        if args.no_filters:
            must_not: list = []
        else:
            must_not, _, _ = load_with_remap(FILTERS_DIR)

        sensors = None
        if args.sensor and args.sensor.lower() != "all":
            sensors = [s.strip() for s in args.sensor.split(",")]

        extra_must = module.build_extra_must(search_params)
        body, _ = build_base_query(
            must_not=must_not,
            extra_must=extra_must,
            source_fields=module.SOURCE_FIELDS,
            limit=args.limit,
            time_range=args.time_range,
            sensors=sensors,
            datasets=module.DATASETS,
            public_only=args.public_only,
            src_ip_filter=args.src_ip,
            direction=args.direction,
        )
        print(json.dumps(body, indent=2))
        return

    # 7. Execute query
    records = run_query(module, search_params)
    if not records:
        console.print(
            "[yellow]No records returned. Filters may be too aggressive or data may be sparse.[/yellow]"
        )
        return

    # 8. Display results
    module.display(records)

    # 9. Interactive loop
    if not args.no_interactive:
        interactive_loop(records, search_params, module)


if __name__ == "__main__":
    main()
