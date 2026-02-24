# Project Structure

```
pisces-scripts/
├── src/
│   ├── querier/                    # Query engines and filter management
│   │   ├── kibana_querier.py       # Kibana/Suricata entry point — query, display, interactive loop
│   │   ├── opensearch_querier.py   # Malcolm/Zeek entry point — thin dispatcher, delegates to zeek_modules/
│   │   ├── filter_loader.py        # Loads and merges YAML filter files into ES must_not clauses
│   │   ├── fp_manager.py           # Interactive false positive filter creator
│   │   └── zeek_modules/           # Per-protocol Zeek log modules
│   │       ├── __init__.py         # MODULES registry dict
│   │       ├── base.py             # Shared infrastructure: query building, dedup, interactive loop
│   │       ├── conn.py             # Zeek conn log (TCP/UDP/ICMP connections)
│   │       ├── dns.py              # Zeek dns log (DNS queries and responses)
│   │       ├── http.py             # Zeek http log (HTTP requests)
│   │       ├── ssl.py              # Zeek ssl log (TLS/SSL handshakes)
│   │       ├── smtp.py             # Zeek smtp log (email sessions)
│   │       ├── rdp.py              # Zeek rdp log (Remote Desktop Protocol)
│   │       ├── smb.py              # Zeek smb_files + smb_mapping (combined)
│   │       ├── ssh.py              # Zeek ssh log (SSH connections and auth)
│   │       ├── notice.py           # Zeek notice log (with broad/narrow FP scope)
│   │       └── weird.py            # Zeek weird log (unusual protocol behaviour)
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
│   ├── composite/                  # Multi-field (IP + port + signature) rules
│   └── notices/                    # Narrow Zeek notice suppression rules (src_ip + notice.note)
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

### `src/querier/opensearch_querier.py`
Malcolm/Zeek analyst tool targeting the OpenSearch instance. On launch it:
1. Pre-parses `--log-type` and loads the matching protocol module from `zeek_modules/`
2. Builds a combined argparse parser (shared args + module-specific args)
3. Loads and merges all enabled YAML filters, remapping Kibana field names to Malcolm field names
4. Queries Malcolm's `arkime_sessions3-*` index, parses and deduplicates hits using module logic
5. Displays a protocol-specific Rich table, then enters an interactive loop

### `src/querier/zeek_modules/`
Per-protocol Zeek modules. Each module implements the `ZeekModule` interface defined in `base.py`:
- `DATASETS` — list of `event.dataset` values to query (e.g. `["smb_files", "smb_mapping"]`)
- `SOURCE_FIELDS` — `_source` fields to request from OpenSearch
- `build_extra_must(search_params)` — protocol-specific filter clauses from CLI args
- `parse_hit(src)` — normalise one `_source` dict into a record dict
- `dedup_key(record)` — grouping key for deduplication
- `display(records)` — render a protocol-specific Rich table
- `add_args(parser)` — register protocol-specific CLI flags
- `describe_record(record)` — one-line hint for the interactive loop
- `fp_signature(record)` — signature string for FP alert dict
- `fp_action(record)` — handle `[f]` action (notice.py overrides to offer broad/narrow scope)

### `src/querier/filter_loader.py`
Walks `filters/` recursively, loads every enabled YAML file, and strips `comment` keys before merging clauses into the final ES query. Reloaded on every re-search so filters written mid-session take effect immediately.

### `src/querier/fp_manager.py`
Guides the analyst through building a new filter interactively: category → subcategory → clause type → values → optional comment. Writes the result to the appropriate YAML file and updates `categories.yaml` if the subcategory is new.
