# Mantis Threat Model Generator

The threat model generator (`src/mantis/mantis_threat_model.py`) reads the local
ticket index produced by `mantis_index.py` and classifies every ticket to build five
IP registries. These registries are what the Mantis web app displays.

The indexer and threat model generator are two separate steps — run them in order:

```bash
uv run src/mantis/mantis_index.py          # step 1: fetch tickets from API
uv run src/mantis/mantis_threat_model.py   # step 2: classify and build registries
```

---

## Output files

All files are written to `data/tickets/enriched/`:

| File | What it contains |
|---|---|
| `malicious_ips.json` | Confirmed threat IPs — attack types, CVEs, blocklist hits, ticket count |
| `false_positive_ips.json` | IPs flagged as likely false positives, with confidence score and source tickets |
| `known_infra_ips.json` | Known infrastructure IPs — CDN, cloud providers, authorised scanners |
| `dns_resolver_ips.json` | Known public DNS resolver IPs extracted from ticket history |
| `undetermined_ips.json` | IPs the classifier couldn't confidently resolve either way |

The Mantis web app reads these files at startup. After any run of the threat model
generator, restart the web UI (or reload it if it's already running) to pick up the
new data.

---

## Flags

### `--classify-stats`

Print a breakdown of how all tickets were classified after the run:

```bash
uv run src/mantis/mantis_threat_model.py --classify-stats
```

Output includes:
- Disposition counts (true positive / false positive / benign / undetermined) with percentages
- Threat type breakdown for confirmed threat tickets
- Actor breakdown for benign/authorized activity tickets

Useful after a large index rebuild to sanity-check the dataset before triaging.

---

### `--enrich`

For IPs that the rule-based classifier couldn't resolve (the undetermined group), run
a live API enrichment pass using GreyNoise and AbuseIPDB to attempt a verdict:

```bash
uv run src/mantis/mantis_threat_model.py --enrich
```

Requires `GREYNOISE_API_KEY` and/or `ABUSEIPDB_API_KEY` in your `.env`. Results are
cached with a 30-day TTL in `data/enrichment_cache.json` — repeat runs won't re-query
recently enriched IPs. After enrichment, all five registries are automatically
regenerated with the updated signals.

Use this when you have API keys available and want to reduce the size of the
undetermined group.

---

### `--input`

Override the default index file location:

```bash
uv run src/mantis/mantis_threat_model.py --input /path/to/tickets_index.json
```

---

## Conflict resolution

An IP can appear in ticket history as both a confirmed threat (in one set of tickets)
and a false positive (in another). The generator resolves these automatically:

- If the FP evidence is at least 3× the threat evidence → kept in FP only
- If the threat evidence is at least 3× the FP evidence → kept in malicious only
- Otherwise → moved to undetermined with a `registry_conflict` signal

Conflicts are reported to the terminal at the end of the run.

---

## Recommended schedule

Run both steps at the start of each shift:

```bash
uv run src/mantis/mantis_index.py
uv run src/mantis/mantis_threat_model.py
```

Or set up a nightly cron job to keep the registries fresh automatically.

---

## Related

- [Mantis Integration](mantis.md) — indexing, ticket search, and FP candidate generation
- [Getting Started](getting-started.md) — first-time setup walkthrough
