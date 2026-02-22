# PISCES SOC Analyst Toolkit

A Python-based security operations toolkit for querying, filtering, enriching, and triaging Suricata IDS alerts from the PISCES program dataset. Built to reduce false positive noise through analyst-maintained YAML filters and structured threat intelligence enrichment.

## Overview

This tool addresses the core challenge of working with high-volume IDS alert data: surfacing actionable threats while suppressing known false positives. It provides:

- **Pre-query filtering** via YAML-defined Elasticsearch DSL `must_not` clauses
- **Threat intelligence enrichment** through GreyNoise and AbuseIPDB APIs
- **Interactive false positive management** for rapid filter creation
- **Mantis ticketing integration** for incident tracking and submission

## Features

### 1. Kibana Alert Querying (`src/querier/kibana_querier.py`)
- Query Suricata alerts from Kibana with flexible time ranges, severity levels, and city filters
- Inject analyst-maintained false positive filters before query execution
- Aggregate and deduplicate results by source IP and signature
- Interactive post-query actions: enrich, create FP filter, search Mantis, create ticket

### 2. False Positive Filter Management (`src/querier/fp_manager.py`)
- Create and manage YAML-based filters organized by category (IPs, signatures, ports, composite)
- Interactive filter creation from alert context
- Validate filter syntax and structure
- Auto-sync filter registry (`filters/categories.yaml`)

### 3. Threat Intelligence Enrichment (`src/enricher/`)
- **GreyNoise**: Gate enrichment pipeline—benign IPs can be added to FP filters
- **AbuseIPDB**: Corroborate malicious classifications with abuse confidence scores
- Raw data presentation for analyst judgment (no automated scoring)

### 4. Mantis Integration (`src/mantis/`)
- Search existing tickets (offline index + live web scraping)
- Interactive ticket creation and submission

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd pisces-scripts

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure credentials
cp .env.example .env
# Edit .env with your API keys and credentials
```

## Configuration

Create a `.env` file with the following credentials:

```bash
KIBANA_USERNAME=your_username
KIBANA_PASSWORD=your_password
GREYNOISE_API_KEY=your_greynoise_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
MANTIS_USERNAME=your_mantis_username
MANTIS_PASSWORD=your_mantis_password
MANTIS_API_URL=your_mantis_api_url
MANTIS_API_TOKEN=your_mantis_token
```

## Usage

### Query Kibana Alerts

```bash
# Basic query (last 24 hours, severity 3, all cities)
python src/querier/kibana_querier.py

# Custom time range and severity
python src/querier/kibana_querier.py --time-range now-7d --severity 2

# Filter by cities and public IPs only
python src/querier/kibana_querier.py --cities <city-1>,<city-2> --public-only

# Filter by signature pattern
python src/querier/kibana_querier.py --signature "ET TROJAN"

# Limit results
python src/querier/kibana_querier.py --limit 100
```

### Manage False Positive Filters

```bash
# List all filters
python src/querier/fp_manager.py --list

# Validate filter syntax
python src/querier/fp_manager.py --validate

# Create new filter interactively
python src/querier/fp_manager.py
```

### Enrich IP Addresses

```bash
# Standalone enrichment
python src/enricher/threat_intel.py --ip 185.220.101.45
```

### Search Mantis Tickets

```bash
# Search for tickets by IP or keyword
python src/mantis/mantis_search.py --query "185.220.101.45"
```

## Project Structure

```
pisces-scripts/
├── src/
│   ├── querier/          # Kibana query and filter management
│   │   ├── kibana_querier.py
│   │   ├── filter_loader.py
│   │   └── fp_manager.py
│   ├── enricher/         # Threat intelligence APIs
│   │   ├── threat_intel.py
│   │   ├── greynoise.py
│   │   └── abuseipdb.py
│   ├── mantis/           # Ticketing integration
│   │   ├── mantis_search.py
│   │   └── mantis_submit.py
│   └── utils/            # Shared utilities
│       └── dns.py
├── filters/              # YAML false positive filters
│   ├── categories.yaml
│   ├── ips/
│   ├── signatures/
│   ├── ports/
│   └── composite/
├── data/
│   ├── cache/           # Kibana response cache (gitignored)
│   └── tickets/         # Mantis ticket index
├── .env                 # Credentials (gitignored)
├── .env.example         # Template
├── requirements.txt
└── SPEC.md             # Detailed implementation specification
```

## Filter Schema

Filters are YAML files with Elasticsearch DSL `must_not` clauses:

```yaml
# filters/ips/known_scanners.yaml
description: "Known research and internet scanners"
author: analyst_name
date_added: 2026-02-21
category: ips
subcategory: known_scanners
enabled: true
must_not:
  - term:
      src_ip: "71.6.135.131"
  - terms:
      src_ip: ["71.6.165.200", "85.214.149.236"]
```

## Workflow Example

```bash
# 1. Query alerts with filters applied
python src/querier/kibana_querier.py --time-range now-24h --severity 2 --public-only

# Results displayed:
# [1] 185.220.101.45  ET TROJAN   SEV1  <city>  freq:23
# [2] 103.14.8.22     ET SCAN     SEV2  <city>         freq:8

# 2. Enrich suspicious IP
> Action for #1 [e/f/m/t/s]: e
# GreyNoise: not found → AbuseIPDB: 87% confidence, 340 reports

# 3. Create ticket
> Action for #1 [m/t/s]: t
# Interactive ticket creation flow

# 4. Suppress false positive
> Action for #2 [e/f/m/t/s]: f
# Category: ips > known_scanners
# Filter written to filters/ips/known_scanners.yaml
```

## Dependencies

- `requests` - HTTP client for API calls
- `python-dotenv` - Environment variable management
- `pyyaml` - YAML filter parsing
- `rich` - Terminal formatting and tables
- `beautifulsoup4` - Mantis web scraping

## License

See [LICENSE](LICENSE) file for details.