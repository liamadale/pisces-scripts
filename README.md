![](https://pisces-intl.org/wp-content/uploads/2025/03/PISCES-white.png)

[![CI](https://github.com/liamadale/pisces-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/liamadale/pisces-scripts/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/liamadale/pisces-scripts/badge)](https://scorecard.dev/viewer/?uri=github.com/liamadale/pisces-scripts)

# PISCES SOC Analyst Toolkit

A Python-based security operations toolkit for querying, filtering, enriching, and triaging network log data from the PISCES program dataset. Targets **Malcolm** (Zeek + Suricata + Arkime) via OpenSearch. Built to reduce false positive noise through analyst-maintained YAML filters and structured threat intelligence enrichment.

## Overview

The toolkit surfaces actionable threats from high-volume log data by combining:

- **Pre-query filtering** via YAML-defined Elasticsearch DSL `must_not` clauses, reloaded on every search
- **Threat intelligence enrichment** through GreyNoise, AbuseIPDB, Shodan, and VirusTotal
- **IP organisation identification** — CDN, cloud provider, and known scanner recognition (Shodan, Censys, Stretchoid, etc.) with automatic range updates
- **Interactive false positive management** for rapid filter creation with comment support
- **Mantis ticketing integration** for incident tracking and submission

## Development Transparency - Use of AI Tooling

This project was created with the assistance of AI coding tools. AI was used to:
- Generate initial code implementations
- Draft documentation and usage examples

All AI-generated content has been reviewed and tested by a human.

## Features

### 1. Malcolm/Zeek OpenSearch Querier (`src/querier/opensearch_querier.py`)
Query Zeek protocol logs from Malcolm's OpenSearch instance across 10 log types: `conn`, `dns`, `http`, `ssl`, `smtp`, `rdp`, `smb`, `ssh`, `notice`, and `weird`. Per-protocol modules handle field parsing, deduplication, and display. Shared interactive loop supports enrichment, FP filter creation, Mantis search, and ticket submission from any log type.

### 2. False Positive Filter Management (`src/querier/fp_manager.py`)
Create YAML filters interactively from alert context, seeded with IP, signature, and sensor. Optional comment field auto-suggested from GreyNoise enrichment results. Filters take effect on the next `[r]`e-search without restarting the tool. See [docs/filter-schema.md](docs/filter-schema.md) for the full schema and authoring guide.

### 3. Threat Intelligence Enrichment (`src/enricher/threat_intel.py`)
Pipeline runs in order for each IP:
1. **GreyNoise** — classification (benign/malicious/unknown), name, reason; if benign, offer FP filter and stop
2. **AbuseIPDB** — confidence score, report count, ISP, domain, usage type
3. **Shodan** — open ports, OS, org, hostnames, known CVEs
4. **VirusTotal** — vendor detection count breakdown, ASN, country
5. **Reference URLs** — links to all four services always printed at the end

### 4. Mantis Integration (`src/mantis/`)
Search existing tickets via offline index or live web scraping.

### 5. Web UIs (`apps/`)
Four browser-based Flask + HTMX applications served together through a central hub portal. Start everything at once with `run_all.py` (recommended), or run each app standalone on its own port.

| App | Path (combined) | Standalone launcher | Standalone port | Purpose |
|---|---|---|---|---|
| **Hub** | `/` | — | 5000 | Landing page with links to all apps |
| **OpenSearch** | `/opensearch` | `opensearch_web_run.py` | 5001 | Cross-protocol Zeek IP activity matrix, per-protocol drill-down, inline enrichment |
| **Mantis** | `/mantis` | `mantis_web_run.py` | 5003 | Ticket browser and threat modelling dashboard |
| **Dashboard** | `/dashboard` | `dashboard_web_run.py` | 5004 | Aggregated analytics dashboard |

The OpenSearch app's overview page shows how many times each source IP appears across all 10 Zeek log types simultaneously — a cross-protocol correlation not achievable in the CLI.

**OpenSearch Web UI** — cross-protocol IP activity matrix showing hit counts across all 10 Zeek log types, with per-protocol drill-down and inline enrichment.

<img src="docs/assets/pisces-scripts-opensearch-webapp.png" width="700" alt="OpenSearch Web UI">

**Mantis Web UI** — ticket browser with threat modelling dashboard, disposition scoring, and known malicious IP tracking.

<img src="docs/assets/pisces-scripts-mantis-webapp.png" width="700" alt="Mantis Web UI">

**Dashboard Web UI** — aggregated analytics in one view. Three tabbed sections:
- **Overview** — stat row (tickets, malicious/FP IPs, active sensors, OS notices) and IP verdict distribution donut
- **OpenSearch** — protocol breakdown, sensor activity, top source IPs; plus a "Malcolm Dashboards" sub-tab with protocol-specific Zeek charts (DNS query types/domains/rcodes, HTTP methods/status codes/hosts/user agents, SSL/TLS versions/ciphers/SNI/validation, connection states/ports/bytes)
- **Threat Intel** — attack type distribution, blocklist sources, monthly ticket timeline, top threat IPs table

All sections are lazy-loaded via HTMX on first tab activation and cached server-side (configurable TTL via `PISCES_DASHBOARD_CACHE_TTL`).

## Installation

This project uses [uv](https://github.com/astral-sh/uv) for dependency management. Install it first if you haven't:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then:

```bash
git clone <repository-url>
cd pisces-scripts
uv sync
cp .env.example .env  # edit with your credentials
```

Run scripts with `uv run <script>` — no manual venv activation needed.

### Optional features

The core install covers the CLI queriers, web UIs, and enrichment pipeline. Additional features are opt-in:

| Extra | What it enables | Install |
|---|---|---|
| `mcp` | MCP servers for AI assistant integration (Claude Code, Claude Desktop) | `uv sync --extra mcp` |
| `ml` | ML-based ticket classifier in `mantis_index.py --use-ml` | `uv sync --extra ml` |
| `all` | Everything above | `uv sync --extra all` |

For example, to enable MCP servers and the ML classifier:

```bash
uv sync --extra mcp --extra ml
```

<details>
<summary>Alternative: plain venv + pip</summary>

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Optional features — install any combination:
pip install -r mcp/requirements.txt                          # MCP servers
pip install -r src/mantis/ticket_enrichment/requirements.txt # ML classifier
```
</details>

## Configuration

```bash
# OpenSearch / Malcolm (opensearch_querier.py, opensearch web UI, MCP opensearch server)
PISCES_USERNAME=
PISCES_PASSWORD=
OPENSEARCH_URL=      # base URL only — /api/console/proxy is appended automatically

# Threat intelligence enrichment (all optional — missing keys skip that service)
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=

# Mantis ticketing
MANTIS_API_URL=
MANTIS_API_TOKEN=
```

## Usage

### Web UIs

```bash
uv run run_all.py   # hub at http://0.0.0.0:5000
```

### CLI Queriers

```bash
uv run src/querier/opensearch_querier.py --log-type conn --public-only
uv run src/querier/opensearch_querier.py --list-log-types
```

### Enrichment & Filters

```bash
uv run src/enricher/threat_intel.py --ip 185.220.101.45
uv run src/querier/fp_manager.py --list
```

See [docs/advanced-usage.md](docs/advanced-usage.md) for the full command reference.

## MCP Servers (AI Assistant Integration)

Three MCP servers expose the same backends to AI coding assistants (Claude Code, Claude Desktop, kiro-cli):

| Server | Path | Tools |
|---|---|---|
| `opensearch` | `mcp/opensearch/` | 16 — Zeek logs, pivot tools, utilities |
| `mantis` | `mcp/mantis/` | 2 — MantisBT ticket search |
| `enrichment` | `mcp/enrichment/` | 2 — IP threat intelligence and org lookup, no backend required |

See [docs/mcp-servers.md](docs/mcp-servers.md) for setup instructions, client configuration, and full tool reference.

## Workflow

See [docs/workflow.md](docs/workflow.md) for a full end-to-end walkthrough including triage patterns, mid-session filter creation, and prompt navigation.

## Project Structure

See [docs/project-structure.md](docs/project-structure.md) for the full annotated tree.

```
pisces-scripts/
├── run_all.py                # Combined launcher — all apps on one port (recommended)
├── opensearch_web_run.py     # Standalone OpenSearch web UI launcher → apps/opensearch_web/
├── mantis_web_run.py         # Standalone Mantis web UI launcher → apps/mantis_web/
├── dashboard_web_run.py      # Standalone Dashboard launcher → apps/dashboard_web/
├── apps/
│   ├── hub/                  # Hub portal (landing page, links to all apps)
│   ├── opensearch_web/       # Flask + HTMX Zeek/OpenSearch UI (port 5001 standalone)
│   ├── mantis_web/           # Flask ticket browser (port 5003 standalone)
│   └── dashboard_web/        # Flask + HTMX aggregated analytics dashboard (port 5004 standalone)
│       ├── overview/         # Cross-source stat row + verdict donut
│       ├── opensearch/       # Protocol/sensor/IP charts + per-protocol Zeek panels
│       └── mantis/           # Attack types, blocklists, timeline, top IPs
├── src/
│   ├── querier/            # OpenSearch querier, filter management
│   │   └── zeek_modules/   # Per-protocol Zeek log modules (conn, dns, http, …)
│   ├── enricher/           # GreyNoise, AbuseIPDB, Shodan, VirusTotal
│   ├── mantis/             # Ticket search and submission
│   └── utils/              # DNS helpers, IP org identification, formatting
├── filters/                # Analyst-maintained YAML false positive filters
├── mcp/                    # MCP servers for AI assistant integration
├── reports/                # Analyst incident reports (Markdown)
├── docs/                   # Extended documentation
└── data/                   # Runtime cache (cloud IP ranges, Stretchoid list, Mantis index)
```

## Filter Schema

See [docs/filter-schema.md](docs/filter-schema.md) for the full schema, clause types, comment field usage, and a guide to adding new filters.

## Dependencies

- `requests` — HTTP client for OpenSearch and enrichment APIs
- `python-dotenv` — credential loading from `.env`
- `pyyaml` — YAML filter parsing
- `rich` — terminal tables and formatting
- `beautifulsoup4` — Mantis web scraping
- `flask` — web UI server

## License

See [LICENSE](LICENSE) for details.
