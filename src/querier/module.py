#!/usr/bin/env python3
"""ZeekModule abstract base class — protocol module interface."""

from src.querier.client import console


class ZeekModule:
    """Protocol module interface. Subclass and override methods as needed."""

    DATASETS: list = ["all"]
    SOURCE_FIELDS: list = []
    DETAIL_FIELDS: list = []  # List of (label: str, value_fn: Callable[[dict], str])
    SENSOR_PARAM: str | None = "sensor"  # Set to None to skip the sensor prompt in re-search
    SUPPORTS_IP_FILTER: bool = True  # Set False for metadata-only modules (pe, capture_loss)
    SUPPORTS_ENRICHMENT: bool = True  # Set False for modules with no IPs or hashes to enrich
    SUPPORTS_FP: bool = True  # Set False for diagnostic modules (capture_loss)
    WEB_CATEGORY: str = "core"  # Category group for the web UI sidebar
    WEB_ICON: str = "fa-question"  # Font Awesome icon class for the web UI sidebar
    WEB_COLUMNS: list = []  # List of (header: str, value_fn: Callable[[dict], str]) for web table
    EXTRA_PARAMS: list[str] = []  # Protocol-specific search_params keys forwarded from HTTP request
    SUMMARY_FIELD: str | None = None  # OpenSearch field to aggregate on for the browse modal
    SUMMARY_PARAM: str | None = None  # EXTRA_PARAMS key that filters on SUMMARY_FIELD
    SUMMARY_TYPE: str = "flat"  # "flat" = single field agg, "grouped" = scripted prefix + severity

    def build_extra_must(self, search_params: dict) -> tuple:
        """Return (must_clauses, post_filters) built from search_params.

        must_clauses: list of OpenSearch DSL clause dicts added to the query must.
        post_filters: list of callables (record: dict) -> bool applied after parsing.
                      When non-empty, run_query() uses 3× over-fetch automatically.
        """
        return [], []

    def prepare_hits(self, hits: list) -> None:
        """Pre-parse hook called on raw hits before parse_hit() loop.

        Override for batch lookups (e.g. x509 community_id pivot, pe fuid→hash lookup).
        Default is a no-op.
        """

    def parse_hit(self, src: dict) -> dict:
        """Convert an OpenSearch _source dict to a normalised record dict.

        Must include at minimum: timestamp, sensor, src_ip, dest_ip,
        dest_port, src_port, _raw.
        """
        raise NotImplementedError

    def dedup_key(self, record: dict) -> tuple:
        """Return the grouping key tuple for deduplicate_zeek."""
        raise NotImplementedError

    def display(self, records: list) -> None:
        """Render records as a Rich table."""
        raise NotImplementedError

    def display_detail(self, record: dict, idx: int) -> None:
        """Render a Rich Panel with every DETAIL_FIELDS field for the selected record."""
        from rich.panel import Panel
        from rich.table import Table

        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="dim", no_wrap=True, min_width=12)
        grid.add_column(overflow="fold")
        for label, fn in self.DETAIL_FIELDS:
            grid.add_row(label, fn(record))
        console.print(
            Panel(
                grid,
                title=f"[bold]#{idx}[/bold]  {self.describe_record(record)}",
                expand=False,
            )
        )

    def add_args(self, parser) -> None:
        """Add protocol-specific argparse arguments to the shared parser."""
        pass

    def describe_record(self, record: dict) -> str:
        """One-line summary used in the interactive loop hint line."""
        src = record.get("src_ip", "?")
        dst = record.get("dest_ip", "?")
        port = record.get("dest_port", "?")
        return f"{src} → {dst}:{port}"

    def fp_signature(self, record: dict) -> str:
        """Signature string embedded in the FP alert dict."""
        return "zeek/unknown"

    def fp_action(self, record: dict) -> None:
        """Handle the [f]alse positive action. Override for custom behaviour."""
        from src.querier.fp_manager import create_filter_interactive

        fp_alert = {
            "src_ip": record.get("src_ip"),
            "dest_ip": record.get("dest_ip"),
            "dest_port": record.get("dest_port"),
            "alert": {
                "signature": self.fp_signature(record),
                "severity": 3,
            },
            "clientID": (record.get("sensors") or [record.get("sensor", "")])[0],
        }
        create_filter_interactive(alert=fp_alert)

    def add_search_params_prompt(self, new: dict, _ask) -> None:
        """Prompt for protocol-specific re-search parameters.

        Override to append module-specific fields to `new`.
        `_ask(label, current_val)` returns the user-entered string or the
        current value's string form if the user pressed Enter.
        """
        pass
