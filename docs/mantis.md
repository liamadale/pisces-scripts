# Mantis Integration

PISCES integrates with MantisBT for ticket lookup and index-driven threat intelligence.
Two scripts handle this — the indexer builds a local snapshot of the PISCES ticket
dataset, and the search tool queries it.

For building the threat model and IP registries from the index, see
[mantis-threat-model.md](mantis-threat-model.md).

---

## Scripts

| Script | Purpose |
|---|---|
| `src/mantis/mantis_index.py` | Fetch the PISCES ticket dataset into a local index |
| `src/mantis/mantis_search.py` | Search tickets by IP, keyword, or phrase |

---

## mantis_index.py

Paginates the MantisBT REST API and writes every ticket to a local JSON index at
`data/tickets/indexed/tickets_index.json`. A progress bar shows pages fetched and
elapsed time. If a page times out, the indexer retries once before stopping and
preserving what it already collected.

### Flags

```bash
# Full index — recommended
uv run src/mantis/mantis_index.py

# Smoke test: fetch only the first ~150 tickets
uv run src/mantis/mantis_index.py --max-pages 3

# Reprocess the existing index without fetching from the API
uv run src/mantis/mantis_index.py --from-index

# Custom output path
uv run src/mantis/mantis_index.py --output /path/to/tickets_index.json
```

| Flag | Default | Purpose |
|---|---|---|
| `--max-pages` | unlimited | Stop after N pages (~50 tickets each) — useful for smoke tests |
| `--from-index` | off | Reprocess existing index without making any API calls |
| `--output` | `data/tickets/indexed/tickets_index.json` | Override the output path |

### Recommended schedule

Run at the start of each shift to pick up tickets created since the last run. Any
ticket not yet in the local index is still reachable via the live API fallback during
search.

---

## Ticket schema

Every ticket in the index follows this structure:

```json
{
    "id": "12345",
    "url": "https://mantis.example.internal/view.php?id=12345",
    "status": "resolved",
    "resolution": "fixed",
    "severity": "major",
    "priority": "normal",
    "created_at": "2026-02-10",
    "updated_at": "2026-02-12",
    "project": "example-city",
    "category": "Example College",
    "reporter": {"id": 101, "name": "j.analyst"},
    "handler": {"id": 42,  "name": "s.lead"},
    "summary": "Reconnaissance Campaign from 198.51.100.22",
    "description": "...",
    "steps_to_reproduce": "https://opensearch.example.internal/goto/...",
    "additional_information": "https://viz.greynoise.io/ip/198.51.100.22",
    "notes": [
        {
            "id": 9001,
            "reporter": {"id": 42, "name": "s.lead"},
            "text": "Confirmed scanning activity — recommend block.",
            "created_at": "2026-02-12T09:15:00-08:00",
            "is_admin_note": true
        }
    ],
    "ips": ["198.51.100.22", "203.0.113.5"],
    "dashboard_links": ["https://opensearch.example.internal/goto/..."],
    "ti_links": ["https://viz.greynoise.io/ip/198.51.100.22"],
    "note_count": 3,
    "admin_note_count": 1
}
```

### Admin notes

A note is flagged `is_admin_note: true` when its author matches the ticket's assigned
handler. In practice only SOC leads and managers can be assigned as handlers, so
handler-authored notes are a reliable signal for verdicts and recommendations.

In the web UI, admin notes appear as highlighted callouts beneath each ticket card. In
the CLI, they are printed as `★` sub-rows under the ticket table row.

### IP extraction

The indexer extracts IPs from all free-text fields — `description`,
`steps_to_reproduce`, `additional_information`, and note bodies. Both standard
(`198.51.100.22`) and defanged (`198.51.100[.]22`) notation are recognised. Private
and loopback addresses are excluded automatically.

---

## mantis_search.py

Search the PISCES ticket dataset by IP address, keyword, or phrase.

```bash
# Search by IP
uv run src/mantis/mantis_search.py --query 198.51.100.22

# Search by keyword or alert signature
uv run src/mantis/mantis_search.py --query "ET SCAN Nmap"

# Scope to a specific city project
uv run src/mantis/mantis_search.py --query 198.51.100.22 --city example-city
```

### Search priority

All three sources are always queried and results are merged. Live API results take
precedence over the index for the same ticket ID.

```
1. Offline index   — instant, full PISCES dataset history
2. REST API        — recent tickets, full fields
3. Web scraping    — fallback if REST API returns nothing
```

If the index hasn't been built yet, the CLI still works via the live API — it just
won't have full historical coverage.

### Reading results

```
 Mantis Tickets (2 found)
 ──────────────────────────────────────────────────────────────────────────────
  ID     Summary                              Status    Sev    Handler    Notes
 ──────────────────────────────────────────────────────────────────────────────
  12345  Reconnaissance Campaign from 198.…   resolved  major  s.lead     3 (1★)
         ★ Confirmed scanning — recommend block.
  11200  Possible C2 Beacon 198.51.100.22     closed    minor  s.lead     1
 ──────────────────────────────────────────────────────────────────────────────
```

What to look for:

- **Resolved/closed with an admin note** → the IP has been investigated; the `★` note
  contains the SOC lead's verdict
- **Open/acknowledged** → a ticket exists and is being worked; check the handler before
  creating a duplicate
- **No results** → no prior history in the PISCES dataset; consider enriching the IP
  and opening a ticket in MantisBT

### Sensor-aware project scoping

When called from the CLI interactive loop (`[m]` action) or the web UI, search
automatically scopes to the project matching the sensor that captured the record. A
record from `hedgehog-example-city` will scope results to the `example-city` project,
even when viewing an all-sensors overview.

---

## Required environment variables

```bash
MANTIS_API_URL=https://mantis.example.internal   # base URL, no trailing slash
MANTIS_API_TOKEN=<your API token>                 # for REST API access
PISCES_USERNAME=<username>                        # for web scraping fallback
PISCES_PASSWORD=<password>                        # for web scraping fallback
```

`MANTIS_API_TOKEN` is required for the indexer and the primary search path. The
scraping fallback only activates if the REST API returns no results.
