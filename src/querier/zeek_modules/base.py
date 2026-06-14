#!/usr/bin/env python3
"""Backwards-compatibility shim — re-exports everything from the focused querier modules.

Zeek protocol modules import from this file via relative imports (`from .base import …`).
New code should import directly from the focused modules in src/querier/:

    from src.querier.client  import query_opensearch, console
    from src.querier.builder import build_base_query, FIELD_MAP
    from src.querier.runner  import run_query, deduplicate_zeek
    from src.querier.cli_loop import interactive_loop
    from src.querier.module  import ZeekModule
"""

from src.querier.builder import (
    _PRIVATE_CIDR_MUST_NOT,
    _PRIVATE_CIDRS,
    FIELD_MAP,
    TIME_RANGES,
    _remap_clause,
    build_base_query,
    is_private,
    source_terms_script,
)
from src.querier.cli_loop import (
    _search_again_prompt,
    _walk_clauses,
    display_profile,
    interactive_loop,
    list_indices,
    list_log_types,
    list_sensors,
    match_all_sample,
)
from src.querier.client import (
    INDEX,
    OPENSEARCH_URL,
    OpenSearchAuthError,
    OpenSearchConnectionError,
    _opensearch_session,
    console,
    query_opensearch,
)
from src.querier.module import ZeekModule
from src.querier.runner import (
    _OVERFETCH_MULTIPLIER,
    FILTERS_DIR,
    _cache_path,
    _first,
    _fmt_bytes,
    _fmt_dur,
    _load_cache,
    _remap_cache,
    _save_cache,
    _sensor_str,
    deduplicate_zeek,
    load_with_remap,
    run_query,
)

__all__ = [
    # client
    "INDEX",
    "OPENSEARCH_URL",
    "OpenSearchAuthError",
    "OpenSearchConnectionError",
    "_opensearch_session",
    "console",
    "query_opensearch",
    # builder
    "FIELD_MAP",
    "TIME_RANGES",
    "_PRIVATE_CIDRS",
    "_PRIVATE_CIDR_MUST_NOT",
    "_remap_clause",
    "build_base_query",
    "is_private",
    "source_terms_script",
    # runner
    "FILTERS_DIR",
    "_OVERFETCH_MULTIPLIER",
    "_cache_path",
    "_first",
    "_fmt_bytes",
    "_fmt_dur",
    "_load_cache",
    "_remap_cache",
    "_save_cache",
    "_sensor_str",
    "deduplicate_zeek",
    "load_with_remap",
    "run_query",
    # cli_loop
    "_search_again_prompt",
    "_walk_clauses",
    "display_profile",
    "interactive_loop",
    "list_indices",
    "list_log_types",
    "list_sensors",
    "match_all_sample",
    # module
    "ZeekModule",
]
