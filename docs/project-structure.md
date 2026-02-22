# Project Structure

```
pisces-scripts/
├── src/
│   ├── querier/                    # Kibana query engine and filter management
│   │   ├── kibana_querier.py       # Main entry point — query, display, interactive loop
│   │   ├── filter_loader.py        # Loads and merges YAML filter files into ES must_not clauses
│   │   └── fp_manager.py           # Interactive false positive filter creator
│   │
│   ├── enricher/                   # Threat intelligence integrations
│   │   ├── threat_intel.py         # Orchestrator — runs full enrichment pipeline for an IP
│   │   ├── greynoise.py            # GreyNoise Community API (classification, name, reason)
│   │   ├── abuseipdb.py            # AbuseIPDB API (confidence score, reports, ISP)
│   │   ├── shodan.py               # Shodan API (ports, vulns, org, OS, hostnames)
│   │   └── virustotal.py           # VirusTotal API (detection stats, ASN, country)
│   │
│   ├── mantis/                     # MantisBT ticketing integration
│   │   ├── mantis_search.py        # Search tickets via API index or live scraping
│   │   └── mantis_submit.py        # Interactive ticket creation and submission
│   │
│   └── utils/                      # Shared utilities
│       ├── banner.py               # PISCES ASCII banner (Rich Text)
│       └── dns.py                  # DNS resolver setup
│
├── filters/                        # Analyst-maintained YAML false positive filters
│   ├── categories.yaml             # Registry of all categories and subcategories
│   ├── ips/                        # Source IP suppression rules
│   │   ├── known_scanners.yaml         # Research scanners, crawlers (Censys, Shodan, etc.)
│   │   ├── known_bad_blocked.yaml      # Confirmed malicious IPs already actioned/blocked
│   │   ├── network-misconfigurations.yaml  # Misconfigured devices generating noise
│   │   └── normal-flagged-traffic.yaml     # Benign traffic that trips signatures
│   ├── signatures/                 # Alert signature suppression rules
│   │   └── network-misconfiguration.yaml   # SURICATA internal/truncated packet signatures
│   ├── ports/                      # Port-based suppression rules
│   └── composite/                  # Multi-field (IP + port + signature) rules
│
├── data/
│   ├── cache/                      # Kibana response cache — gitignored
│   └── tickets/                    # Mantis ticket index
│
├── docs/                           # Extended documentation
│   ├── project-structure.md        # This file
│   ├── filter-schema.md            # Filter YAML format and authoring guide
│   └── workflow.md                 # End-to-end analyst workflow walkthrough
│
├── .env                            # Credentials — gitignored
├── .env.example                    # Credential template
├── requirements.txt
└── README.md
```

## Module Responsibilities

### `src/querier/kibana_querier.py`
The primary analyst tool. On launch it:
1. Loads and merges all enabled YAML filters into Elasticsearch `must_not` clauses
2. Queries Kibana with the analyst's time/severity/city parameters
3. Deduplicates hits by `(src_ip, signature)` and displays a Rich table
4. Enters an interactive loop — analyst selects an alert number then chooses an action

### `src/enricher/threat_intel.py`
Enrichment pipeline (in order):
1. **GreyNoise** — if benign, offer FP filter creation then print reference URLs and return
2. **AbuseIPDB** — abuse confidence score and report history
3. **Shodan** — open ports, OS, org, known CVEs
4. **VirusTotal** — vendor detection stats
5. **Reference URLs** — always printed for all four services

### `src/querier/filter_loader.py`
Walks `filters/` recursively, loads every enabled YAML file, and strips `comment` keys before merging clauses into the final ES query. Reloaded on every re-search so filters written mid-session take effect immediately.

### `src/querier/fp_manager.py`
Guides the analyst through building a new filter interactively: category → subcategory → clause type → values → optional comment. Writes the result to the appropriate YAML file and updates `categories.yaml` if the subcategory is new.
