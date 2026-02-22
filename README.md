![](https://pisces-intl.org/wp-content/uploads/2025/03/PISCES-white.png)

# PISCES SOC Analyst Toolkit

A Python-based security operations toolkit for querying, filtering, enriching, and triaging Suricata IDS alerts from the PISCES program dataset. Built to reduce false positive noise through analyst-maintained YAML filters and structured threat intelligence enrichment.

## Overview

This tool addresses the core challenge of working with high-volume IDS alert data: surfacing actionable threats while suppressing known false positives. It provides:

- **Pre-query filtering** via YAML-defined Elasticsearch DSL `must_not` clauses, reloaded on every search
- **Threat intelligence enrichment** through GreyNoise, AbuseIPDB, Shodan, and VirusTotal
- **Interactive false positive management** for rapid filter creation with comment support
- **Mantis ticketing integration** for incident tracking and submission

## Features

### 1. Kibana Alert Querying (`src/querier/kibana_querier.py`)
- Query Suricata alerts from Kibana with flexible time range, severity, city, signature, and protocol filters
- Inject analyst-maintained false positive filters before query execution — reloaded from disk on every re-search
- Deduplicate results by `(src_ip, signature)` and display a Rich terminal table
- Interactive loop with last-alert hint and `[p]rint` to redisplay the table without re-querying

### 2. False Positive Filter Management (`src/querier/fp_manager.py`)
- Create YAML filters interactively from alert context, seeded with IP, signature, and city
- Optional comment field auto-suggested from GreyNoise enrichment results
- Filters take effect on the next `[r]`e-search without restarting the tool
- See [docs/filter-schema.md](docs/filter-schema.md) for the full schema and authoring guide

### 3. Threat Intelligence Enrichment (`src/enricher/threat_intel.py`)
Pipeline runs in order for each IP:
1. **GreyNoise** — classification (benign/malicious/unknown), name, reason; if benign, offer FP filter and stop
2. **AbuseIPDB** — confidence score, report count, ISP, domain, usage type
3. **Shodan** — open ports, OS, org, hostnames, known CVEs
4. **VirusTotal** — vendor detection count breakdown, ASN, country
5. **Reference URLs** — links to all four services always printed at the end

### 4. Mantis Integration (`src/mantis/`)
- Search existing tickets via offline index or live web scraping
- Scrape results are filtered to the queried IP to prevent unfiltered default views
- Interactive ticket creation and submission pre-seeded from alert data

## Installation

```bash
git clone <repository-url>
cd pisces-scripts

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

cp .env.example .env
# Edit .env with your credentials
```

## Configuration

```bash
KIBANA_USERNAME=
KIBANA_PASSWORD=
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=
MANTIS_USERNAME=
MANTIS_PASSWORD=
MANTIS_API_URL=
MANTIS_API_TOKEN=
```

API keys for GreyNoise, AbuseIPDB, Shodan, and VirusTotal are each optional — the enricher will print a dim warning and skip the service if a key is missing.

## Usage

### Query Kibana Alerts

```bash
# Basic query (last 24 hours, all severities, all cities)
./src/querier/kibana_querier.py

# Custom time range and severity
./src/querier/kibana_querier.py --time-range now-7d --severity 2

# Filter by cities and public IPs only
./src/querier/kibana_querier.py --cities <city-1>,<city-2> --public-only

# Filter to a specific signature pattern
./src/querier/kibana_querier.py --signature "ET SCAN"

# Print the ES query body without running it
./src/querier/kibana_querier.py --dump-query
```

### Standalone Enrichment

```bash
# Full pipeline
./src/enricher/threat_intel.py --ip 185.220.101.45

# Print reference URLs only (no API calls)
./src/enricher/threat_intel.py --ip 185.220.101.45 --urls-only
```

### Manage False Positive Filters

```bash
# Interactive filter creator
./src/querier/fp_manager.py

# List all filters
./src/querier/fp_manager.py --list

# Validate all filter files
./src/querier/fp_manager.py --validate
```

### Search Mantis Tickets

```bash
./src/mantis/mantis_search.py --query "185.220.101.45"
```

## Workflow

See [docs/workflow.md](docs/workflow.md) for a full end-to-end walkthrough including triage patterns, mid-session filter creation, and prompt navigation.

Quick example:

```
# Launch
./src/querier/kibana_querier.py --time-range now-24h --severity 2 --public-only

# Select alert #2 and enrich
> 2
Alert #2: ET TROJAN Meterpreter | 103.14.8.22
  [e]nrich  [f]alse positive  [m]antis search  [t]icket  [s]kip
  Action: e

# GreyNoise: malicious / AbuseIPDB: 94% / Shodan: ports 9001,9030 (TOR) / VT: 18 vendors

# Create ticket
↩  Last: #2 ET TROJAN Meterpreter | 103.14.8.22
> 2  →  [t]  →  submit ticket

# Suppress a false positive scanner, then re-search
> 7  →  [f]  →  ips / known_scanners
> r  →  alert #7 gone from results

# Reprint table without re-querying
> p
```

## Project Structure

See [docs/project-structure.md](docs/project-structure.md) for the full annotated tree.

```
pisces-scripts/
├── src/
│   ├── querier/        # Kibana querying and filter management
│   ├── enricher/       # GreyNoise, AbuseIPDB, Shodan, VirusTotal
│   ├── mantis/         # Ticket search and submission
│   └── utils/          # Banner, DNS helpers
├── filters/            # Analyst-maintained YAML false positive filters
├── docs/               # Extended documentation
└── data/               # Cache and Mantis ticket index
```

## Filter Schema

See [docs/filter-schema.md](docs/filter-schema.md) for the full schema, clause types, comment field usage, and a guide to adding new filters.

## Dependencies

- `requests` — HTTP client for Kibana and all enrichment APIs
- `python-dotenv` — credential loading from `.env`
- `pyyaml` — YAML filter parsing
- `rich` — terminal tables and formatting
- `beautifulsoup4` — Mantis web scraping

## License

See [LICENSE](LICENSE) for details.
