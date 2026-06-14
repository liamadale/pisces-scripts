# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] — 2026-06-14

### Added

- **Incident correlator** — new Phase 1 orchestrator (`src/correlator/`) that assembles
  incident context from OpenSearch, Mantis tickets, and enrichment in one call.
  Exposed via the MCP `investigate` tool and `/investigate` web pages in
  opensearch_web.
- **Public IP profiler** — `profile_device` now supports public IPs, with sensor
  presence and reverse DNS surfaced in web device cards.
- **Mantis Explorer** — new Flask app for browsing student activity, registered in
  `run_all.py` and the Hub landing page.
- **Hub redesign** — list layout, live data-freshness indicators, settings page with
  theme dropdown, version + git update status in the footer.
- **Theme system** — 8 community themes (Gruvbox, Tokyo Night, Catppuccin variants),
  CSS-variable-driven ECharts colors so charts render correctly on every theme.
- **Shared static blueprint** — `apps/shared/` serves tokens, base CSS, and logos
  across all four web apps; per-app duplicate assets removed.
- **Dashboard** — alert trend chart, triage workqueues, per-sensor log time-series,
  Tickets tab, sensor filter modal, date-range controls wired into the toolbar.
- **MCP OpenSearch tools** — `investigate`, `histogram`, `aggregate`,
  `bulk_enrich_ips`, `count`, `list_filter_categories`, `list_fp_filters`,
  `delete_fp_filter`, `get_notice_summary`, `build_share_urls`,
  `compare_to_baseline`, `enrich_top_talkers`.
- **MCP querier** — port/proto filters, multi-value IP/sensor parameters, absolute
  timestamps, `truncated` flag surfaced on all search results.
- **Wildcard filters** — `notice_note` and `weird_name` accept ES wildcard syntax,
  dispatched to `wildcard` queries with exact-match fallback.
- **Filter loader** — validates category/subcategory pairs against
  `filters/categories.yaml`.
- **FP manager** — `delete_ip_from_filter` extracted into reusable module.
- **Investigate UX** — escalation indicators on ticket cards, Investigate entry-points
  on IP pivot and notice/Suricata records, public device cards, profile buttons.
- **Web UX** — sidebar nav with per-tab persisted filters, sticky-column rendering,
  src/dest/both IP role toggle on ip_pivot, error banners for OpenSearch/Mantis,
  destination IP filter in search bar.
- **Enricher** — `prewarm_enrichment_cache` background warmer, parallel execution
  and result caching on the web enrich path.

### Changed

- **Querier refactor** — `src/querier/zeek_modules/base.py` split into focused
  modules; silent `None` returns replaced with typed exceptions.
- **Web concurrency** — overview route switched from `ThreadPoolExecutor` fan-out
  to `asyncio.gather`; single-flight dedup, shared thread pool, and ETag support
  added; `bool.must` switched to `bool.filter` context for cacheability.
- **MCP package rename** — `mcp/` → `mcp_servers/` to resolve a namespace collision
  with the upstream `mcp` package. **Breaking** for anyone importing the old path.
- **App rename** — `mantis_web` → `threat_model`. **Breaking** for any external
  bookmarks or imports referencing the old name.
- **Pivot/profile/investigate** and `aggregate` MCP tools consolidated.
- **Mantis Explorer** — escalation detection rewritten; `is_escalated` surfaced on
  tickets; warning modal added about escalated-count accuracy.
- **Enricher clients** — persistent HTTP sessions, retry adapter, shared console,
  `atexit` cleanup across all enricher modules.
- **Dashboard / OpenSearch panels** — low-signal Malcolm panels pruned; protocol
  bar replaced with time-series area charts; unified to horizontal bars.
- **Hub branding** — heading renamed to "PISCES Toolkit" with toolbox icon; brand
  link navigates to hub; redundant home button removed.
- **OpenSearch web** — search bar redesigned as two-row pill layout; sensor
  selector reworked as single clickable button; Investigate button moved to the
  global search bar; auth history section replaced with search-all-logs.

### Fixed

- **OpenSearch mapping drift** — `terms` aggregations now use a `_source` Painless
  script via `source_terms_script()`, surviving indices whose mapping for the
  same field disagrees (keyword vs text + `.keyword` subfield on rolled-over
  write index).
- **Zeek notice/weird** — exact and wildcard filters now target the `.keyword`
  subfield.
- **Dashboard XSS** — date query parameters sanitised; CodeQL taint chain broken
  by returning parsed ISO-format date.
- **MCP dest_ip** — pushed into the ES query instead of being post-filtered.
- **Web exceptions** — bare `except` handlers that silently swallowed tracebacks
  now log the exception.
- **Cross-protocol query handler** — logs protocol name and error on failure.
- **Querier** — `FilesModule` IP filter flag corrected; `SuricataAlert` summary
  type fix; `build_extra_must` tuple correctly unpacked before
  `build_base_query`.
- **Correlator** — parallel profile fetches, timeline key override, ticket
  deduplication.
- **OpenSearch web** — doubled `script_name` prefix removed from investigate
  HTMX paths; em-dash placeholder IPs skipped in overview table.
- **Threat model / Mantis Explorer** — one-time-per-session notice modal.
- **Surface hierarchy** — Catppuccin and Gruvbox themes corrected.

### Performance

- **HTTP timeout** — sync and async OpenSearch clients bumped from 30s → 60s to
  accommodate slower script aggregations.
- **OpenSearch client cache** — session reused across queries; query construction
  optimised.
- **Filter loader** — mtime-based cache avoids re-parsing YAML on every query.
- **Mantis** — index pagination parallelised; HTTP sessions reused; linear scan
  and per-request sorts replaced with dict lookups in `data.py`.
- **Filter loading / remapping / post-filtering** — redundant work removed.

### Removed

- Root-level standalone app launcher shims.
- `cryptography` dependency dropped; `geoip2` moved to the `offline-enrichment`
  extra.
- `pytest` moved out of main dependencies into dev dependencies.
- Theme toggle buttons removed from per-app navbars (now centralised in Hub
  settings).

### CI

- `djlint` HTML linting added to pre-commit and the CI pipeline.

## [1.0.0] — 2026-XX-XX

Initial tagged release. Dashboard redesign, theming, threat model rename, and
Mantis Explorer (PR #40).

[Unreleased]: https://github.com/liamadale/pisces-scripts/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/liamadale/pisces-scripts/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/liamadale/pisces-scripts/releases/tag/v1.0.0
