# Advanced Usage

## Query Malcolm/Zeek Logs (OpenSearch)

```bash
# List available log types present in the index
uv run src/querier/opensearch_querier.py --list-log-types

# Query conn logs (last 24 hours, public IPs only)
uv run src/querier/opensearch_querier.py --log-type conn --public-only

# Query DNS with a specific query string filter
uv run src/querier/opensearch_querier.py --log-type dns --dns-query malware.example.com

# Narrow to a specific sensor and time window
uv run src/querier/opensearch_querier.py --log-type http --sensor hedgehog-1 --time-range now-6h
```

## Web UIs

Run all apps together via the hub portal (recommended):

```bash
uv run run_all.py                          # hub at http://0.0.0.0:5000
uv run run_all.py --debug
uv run run_all.py --host 127.0.0.1 --port 8080
```

Or run each app standalone:

```bash
uv run opensearch_web_run.py    # http://0.0.0.0:5001
uv run threat_model_run.py      # http://0.0.0.0:5003
uv run dashboard_web_run.py     # http://0.0.0.0:5004
```

All launchers accept `--host`, `--port`, and `--debug` flags.

## Standalone Enrichment

```bash
# Full pipeline
uv run src/enricher/threat_intel.py --ip 185.220.101.45

# Print reference URLs only (no API calls)
uv run src/enricher/threat_intel.py --ip 185.220.101.45 --urls-only
```

## Manage False Positive Filters

```bash
uv run src/querier/fp_manager.py           # interactive filter creator
uv run src/querier/fp_manager.py --list    # list all filters
uv run src/querier/fp_manager.py --validate
```

See [filter-schema.md](filter-schema.md) for the full schema and authoring guide.

## Mantis Index and Threat Model

Rebuild the local ticket index at the start of each shift (or via cron):

```bash
uv run src/mantis/mantis_index.py                # full index
uv run src/mantis/mantis_index.py --max-pages 3  # smoke test (~150 tickets)
uv run src/mantis/mantis_index.py --from-index   # reprocess without API fetch
```

Then run the threat model generator to rebuild the IP registries:

```bash
uv run src/mantis/mantis_threat_model.py                  # build registries
uv run src/mantis/mantis_threat_model.py --classify-stats # with classification breakdown
uv run src/mantis/mantis_threat_model.py --enrich         # + live API enrichment for undetermined IPs
```

See [mantis.md](mantis.md) for indexing and search reference, and
[mantis-threat-model.md](mantis-threat-model.md) for the full threat model flag reference.
