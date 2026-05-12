#!/usr/bin/env python3
"""pisces-histogram — terminal bar chart of Zeek event volume over time."""

import argparse
import os
import shutil
import sys

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.client import OpenSearchAuthError, OpenSearchConnectionError
from src.querier.histogram import query_histogram
from src.querier.zeek_modules import MODULES
from src.utils.dns import setup_dns

_BLOCKS = " ▁▂▃▄▅▆▇█"
_VALID_LOG_TYPES = sorted(MODULES.keys()) + ["all"]


def _render(buckets: list[dict], width: int) -> str:
    """Return a single-row Unicode bar chart string of `width` characters."""
    if not buckets:
        return "(no data)"

    counts = [b["doc_count"] for b in buckets]
    max_count = max(counts) if any(counts) else 1
    n = len(buckets)

    if n <= width:
        bars = [_BLOCKS[round(c / max_count * 8)] for c in counts]
    else:
        # Compress: average counts into `width` columns
        bars = []
        for i in range(width):
            lo = int(i * n / width)
            hi = int((i + 1) * n / width)
            chunk = counts[lo:hi] if lo < hi else counts[lo : lo + 1]
            avg = sum(chunk) / len(chunk)
            bars.append(_BLOCKS[round(avg / max_count * 8)])

    return "".join(bars)


def _time_axis(buckets: list[dict], bar_width: int) -> str:
    """Return a sparse time-label row aligned to the bar chart."""
    if not buckets:
        return ""

    def _short(ts: str) -> str:
        # "2026-04-19T14:00:00.000Z" → "04-19 14:00" or just "HH:MM" if same day
        try:
            date_part, time_part = ts.split("T")
            hhmm = time_part[:5]
            return f"{date_part[5:]} {hhmm}"
        except Exception:
            return ts[:16]

    n = len(buckets)
    label_positions = [0, n // 4, n // 2, 3 * n // 4, n - 1]
    row = [" "] * bar_width

    for pos in label_positions:
        # Map bucket index → bar column
        col = round(pos * bar_width / max(n - 1, 1))
        label = _short(buckets[pos]["key_as_string"])
        start = max(0, min(col, bar_width - len(label)))
        for i, ch in enumerate(label):
            if start + i < bar_width:
                row[start + i] = ch

    return "".join(row)


def main() -> None:
    """Entry point for the pisces-histogram CLI tool."""
    parser = argparse.ArgumentParser(
        description="Show a terminal bar chart of Zeek event volume over time.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "log_type",
        choices=_VALID_LOG_TYPES,
        help="Zeek log type to histogram, or 'all' for every dataset.",
    )
    parser.add_argument(
        "--interval", default="1h", help="Bucket width, e.g. 15m, 1h, 1d (default: 1h)"
    )
    parser.add_argument(
        "--time-range", default="now-24h", help="ES date-math range (default: now-24h)"
    )
    parser.add_argument(
        "--time-from", help="Absolute start timestamp (ISO 8601), overrides --time-range"
    )
    parser.add_argument("--time-to", help="Absolute end timestamp (ISO 8601)")
    parser.add_argument("--src-ip", help="Filter to a source IP (or comma-separated list)")
    parser.add_argument("--dest-ip", help="Filter to a destination IP (or comma-separated list)")
    parser.add_argument("--sensor", default="all", help="Sensor hostname, or 'all' (default)")
    parser.add_argument(
        "--no-filters", action="store_true", help="Disable false-positive YAML filters"
    )
    args = parser.parse_args()

    load_dotenv()
    setup_dns()

    src_ip: str | list[str] | None = args.src_ip
    if args.src_ip and "," in args.src_ip:
        src_ip = [s.strip() for s in args.src_ip.split(",")]
    dest_ip: str | list[str] | None = args.dest_ip
    if args.dest_ip and "," in args.dest_ip:
        dest_ip = [s.strip() for s in args.dest_ip.split(",")]

    try:
        buckets = query_histogram(
            log_type=args.log_type,
            interval=args.interval,
            time_range=args.time_range,
            src_ip=src_ip,
            dest_ip=dest_ip,
            sensor=args.sensor,
            no_filters=args.no_filters,
            time_from=args.time_from,
            time_to=args.time_to,
        )
    except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if not buckets:
        print("No data returned for the given parameters.")
        return

    total = sum(b["doc_count"] for b in buckets)
    max_count = max(b["doc_count"] for b in buckets)
    term_width = shutil.get_terminal_size((120, 24)).columns
    bar_width = min(term_width - 2, len(buckets))

    time_desc = (
        f"{args.time_from}–{args.time_to}" if args.time_from and args.time_to else args.time_range
    )
    header = (
        f"{args.log_type} — {time_desc}, interval={args.interval},"
        f" total={total:,}, max={max_count:,}"
    )
    print(header)
    print(_render(buckets, bar_width))
    print(_time_axis(buckets, bar_width))


if __name__ == "__main__":
    main()
