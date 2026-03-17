# Mantis Integration

PISCES integrates with MantisBT for ticket lookup and index-driven false positive (FP) candidate generation. This document covers the three Mantis scripts, how they interact, and how to get the most out of them.

---

## Scripts

| Script | Purpose |
|---|---|
| `src/mantis/mantis_search.py` | Search for tickets by IP, keyword, or phrase |
| `src/mantis/mantis_index.py` | Bulk-fetch all tickets into a local JSON index |

---

## mantis_index.py — Building the Local Index

The index is the foundation of everything else. Without it, searches are limited to the most recent ~1,000 tickets from the live API. With it, searches cover the full ticket history instantly, with no network calls.

### Running it

```bash
# Full index (all tickets — recommended for production use)
python src/mantis/mantis_index.py

# Smoke test: first 150 tickets only
python src/mantis/mantis_index.py --max-pages 3

# Custom output paths
python src/mantis/mantis_index.py \
    --output data/tickets/tickets_index.json \
    --fp-output data/tickets/fp_ips.txt

# Reprocess existing index with classification stats (no API fetch)
python src/mantis/mantis_index.py --from-index --classify-stats

# Train ML classifier and show stats with ML enabled
python src/mantis/mantis_index.py --from-index --retrain --classify-stats --use-ml
```

### What it does

1. Paginates the MantisBT REST API (`GET /api/rest/issues`) 50 tickets at a time
2. Normalizes each issue into a consistent schema (see below)
3. Writes atomically to `data/tickets/tickets_index.json` (via `.tmp` + rename — no partial writes)
4. Produces `data/tickets/fp_ips.txt` — the FP candidate list (explained below)

A Rich progress bar shows pages fetched and elapsed time. If a page times out, the indexer retries once before stopping and preserving what it already collected.

Three output files are produced:

| File | Contents |
|---|---|
| `data/tickets/tickets_index.json` | Full normalized ticket index (all tickets) |
| `data/tickets/fp_ips.txt` | FP candidate IPs (scored, benign-only) |
| `data/tickets/fp_ips_detail.json` | Per-IP category + score + source tickets |
| `data/tickets/known_malicious_ips.json` | Threat database (malicious IPs with attack metadata) |

### Recommended schedule

Run the indexer at the start of each shift, or via cron nightly. The index is a static snapshot; tickets created after the last run will be caught by the live API fallback during search.

```bash
# Example cron entry: rebuild index every night at 02:00
0 2 * * * cd /path/to/pisces-scripts && .venv/bin/python src/mantis/mantis_index.py
```

---

## Normalized Ticket Schema

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
    "steps_to_reproduce": "https://kibana.example.internal/goto/...",
    "additional_information": "https://viz.greynoise.io/ip/198.51.100.22\n...",
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
    "kibana_links": ["https://kibana.example.internal/goto/..."],
    "ti_links": ["https://viz.greynoise.io/ip/198.51.100.22"],
    "note_count": 3,
    "admin_note_count": 1
}
```

### Admin note detection

A note is flagged `is_admin_note: true` when its author's ID matches the ticket's `handler` ID. In practice, only managers and SOC leads can be assigned as handlers; reporter-level accounts cannot. This makes handler-authored notes a reliable signal for verdicts and recommendations.

In the web UI, admin notes appear as highlighted callouts beneath each ticket card. In the CLI, they are printed as `★` sub-rows under the ticket table row.

### IP extraction

The indexer extracts IPs from all free-text fields — `description`, `steps_to_reproduce`, `additional_information`, and note bodies. Both standard notation (`198.51.100.22`) and defanged notation (`198.51.100[.]22`) are recognized. Private/RFC 1918 and loopback addresses are excluded automatically.

---

## False Positive Candidate Generation

This is produced automatically at the end of every index run.

### The scoring logic

Simply checking `status == resolved/closed` is not enough — roughly 15% of resolved/closed tickets in this dataset are about confirmed malicious IPs that were blocked. Including those in an FP filter list would be counterproductive.

Instead, each ticket is scored and classified before its IPs are collected:

**Positive signals (score each ticket up):**

| Signal | Score | Examples found in data |
|---|---|---|
| Admin note contains FP/benign keyword | +3 | `false positive`, `benign`, `legitimate`, `authorized`, `no action required`, `no indicators of compromise` |
| Resolution = `not a bug` | +3 | Used for traffic correctly identified as not a real issue |
| Resolution = `unable to duplicate` | +2 | Traffic did not recur; can't confirm it was a threat |
| Summary contains FP keyword | +2 | `FP Traffic:`, `Possible False Positive`, `All Attempts Blocked` |
| Admin note mentions known infrastructure | +1 | `CDN`, `Google DNS`, `Censys`, `Cloudflare`, `known scanner` |

**Disqualifiers (score < 0, excluded entirely regardless of status):**

| Signal | Effect | Examples found in data |
|---|---|---|
| Admin note recommends blocking | −5 | `recommend block`, `recommend quarantine`, `block subnet` |
| Admin note calls it malicious | −5 | `malicious`, `threat actor`, `botnet`, `phishing`, `exploit`, `C2 beacon` |
| Summary identifies a confirmed threat | −3 | `ET CINS`, `Known Malicious`, `botnet`, `exploit`, `CVE-`, `malware` |

Only tickets with a **score > 0** and **no disqualifier** contribute IPs to the candidate list.

### Output files

Two files are written:

**`data/tickets/fp_ips.txt`** — flat sorted IP list, one per line. Ready to use with `grep -Ff` or for bulk review.

**`data/tickets/fp_ips_detail.json`** — structured detail per IP:
```json
[
  {
    "ip": "203.0.113.5",
    "disposition": "false_positive",
    "threat_type": null,
    "actor": null,
    "score": 6,
    "ticket_ids": ["1234", "1891"]
  },
  {
    "ip": "198.51.100.22",
    "disposition": "benign_true_positive",
    "threat_type": "vulnerability_scan",
    "actor": "cisa_cyhy",
    "score": 5,
    "ticket_ids": ["2047"]
  }
]
```

Dispositions in the detail file:

| Disposition | Meaning |
|---|---|
| `false_positive` | Alert fired incorrectly (admin FP verdict, `not a bug` resolution, FP summary) |
| `benign_true_positive` | Real activity but authorized/expected (gov scanners, pen tests) |
| `undetermined` | Some positive signal but below the disqualifier threshold — treat with skepticism |

### What to do with the candidate list

The files are a **review list**, not automatic filters. The scoring filters out confirmed threats, but you should still verify before committing:

```bash
# How many candidates did we find?
wc -l data/tickets/fp_ips.txt

# Review high-confidence false positives first
python -c "
import json
data = json.load(open('data/tickets/fp_ips_detail.json'))
for d in data:
    if d['disposition'] == 'false_positive' and d['score'] >= 3:
        print(d['ip'], d['disposition'], 'tickets:', d['ticket_ids'][:3])
"

# Look up what the tickets actually said before committing a filter
python src/mantis/mantis_search.py --query 203.0.113.5
# → check the admin note verdict and resolution

# For IPs confirmed benign, create a filter via CLI [f] or web UI "Create FP Filter"
```

A high score means multiple tickets independently flagged the IP as benign — that's meaningful signal. A `known_infra` score of 1 from a single ticket should be treated with more skepticism than a `benign` score of 6 from three tickets.

---

## Threat Database — known_malicious_ips.json

Also produced on every index run. Built from confirmed-threat tickets (those with malicious/block signals in admin notes or summaries), with structured threat intelligence extracted from every text field.

### Schema

```json
{
  "ip": "198.51.100.22",
  "first_seen": "2024-10-14",
  "last_seen":  "2026-02-17",
  "ticket_ids":   ["10027", "11863", "12403"],
  "ticket_count": 3,
  "attack_types": ["exploit", "port_scan"],
  "cves":         ["CVE-2021-41773", "CVE-2021-42013"],
  "blocklists":   ["et_cins", "abuseipdb", "greynoise"],
  "country":      "NL",
  "isp":          "ExampleHost GmbH",
  "asn":          "AS206996",
  "usage_type":   "Data Center/Web Hosting/Transit",
  "summaries": [
    "ET EXPLOIT Apache HTTP Server Path Traversal Attempt (CVE-2021-42013)",
    "Known Malicious IP attempting port scan"
  ]
}
```

### What gets extracted

| Field | Source | Coverage (150-ticket sample) |
|---|---|---|
| `attack_types` | Summary + admin notes (regex) | ~68% of IPs |
| `cves` | All text fields | ~39% of IPs |
| `country` | Country names/adjectives in notes; emoji flags; `AU Australia` format | ~57% of IPs |
| `isp` | Structured `ISP   <value>` lines in admin notes (copy-pasted from AbuseIPDB) | ~4% of IPs |
| `asn` | `AS<number>` patterns in any field | varies |
| `blocklists` | Mentions of DShield, Spamhaus, ET CINS, GreyNoise, AbuseIPDB, etc. | ~40%+ of IPs |

**Attack types** detected: `exploit`, `port_scan`, `botnet`, `spam_phishing`, `brute_force`, `ddos`, `data_exfil`, `malware`, `iot_attack`

### Caveats

**IPs from the same ticket share the same attribution.** The indexer extracts all IPs mentioned in a ticket — source, destination, and any IPs in the text. If a ticket about a malicious source IP also mentions `8.8.8.8` as the DNS server queried, `8.8.8.8` will appear in the threat DB. Well-known infrastructure IPs (`8.8.8.8`, `1.1.1.1`, CDN ranges) near the top of the list by ticket count should be reviewed and filtered before use.

**Country is extracted from text, not from a GeoIP lookup.** If an analyst writes "Russian-based infrastructure" but the IP geolocates to the Netherlands (not uncommon for leased hosting), the extracted country is `RU`. `ticket_count > 1` provides confidence that the attribution is consistent across multiple independent reports.

### Usage

```bash
# How many IPs are in the threat DB?
python -c "import json; db=json.load(open('data/tickets/known_malicious_ips.json')); print(len(db))"

# All exploit IPs seen in 2+ tickets
python -c "
import json
db = json.load(open('data/tickets/known_malicious_ips.json'))
hits = [r for r in db if 'exploit' in r['attack_types'] and r['ticket_count'] > 1]
for r in hits[:10]:
    print(r['ip'], r['country'], r['cves'][:2], r['ticket_count'], 'tickets')
"

# All IPs with a specific CVE
python -c "
import json
db = json.load(open('data/tickets/known_malicious_ips.json'))
cve = 'CVE-2021-44228'
hits = [r for r in db if cve in r['cves']]
print(f'{len(hits)} IPs exploiting {cve}')
for r in hits[:10]:
    print(f'  {r[\"ip\"]}  {r[\"country\"]}  tickets: {r[\"ticket_count\"]}')
"

# Country breakdown
python -c "
from collections import Counter
import json
db = json.load(open('data/tickets/known_malicious_ips.json'))
print(Counter(r['country'] for r in db if r['country']).most_common(10))
"
```

---

## Ticket Classification System

The indexer classifies every ticket using a hybrid pipeline in `src/mantis/ticket_enrichment/`. Classification drives both FP candidate selection and threat DB construction.

### Three-Dimension Data Model

Each ticket is classified along three dimensions:

| Dimension | Question answered | Values |
|---|---|---|
| **Disposition** | Was the alert real? | `true_positive`, `benign_true_positive`, `false_positive`, `undetermined` |
| **Threat Type** | What kind of activity? | `port_scan`, `exploit`, `malware`, `web_attack`, `ddos`, `botnet`, `brute_force`, `dns_anomaly`, `data_exfil`, `spam_phishing`, `blocklist_hit`, `policy_violation`, `recon`, `vulnerability_scan`, `unknown` |
| **Actor** | Who was responsible? | `cisa_cyhy`, `shadowserver`, `censys`, `rapid7`, `qualys`, `binaryedge`, `stretchoid`, `nessus`, `netspi`, `onyphe`, `leakix`, `other` |

**Disposition meanings:**
- `true_positive` — Confirmed threat; IPs go into the threat database
- `benign_true_positive` — Real activity, but authorized/expected (gov scanner, pen test); IPs go into FP candidates
- `false_positive` — Alert fired incorrectly (wrong traffic, known-safe host); IPs go into FP candidates
- `undetermined` — Not enough evidence to decide; excluded from both outputs

---

### How Classification Works

Each ticket goes through a two-layer pipeline. Layer 1 runs first and covers the vast majority of tickets with no external dependencies. Layer 2 is an optional add-on for tickets that Layer 1 couldn't resolve.

---

### Layer 1: Rule-Based Classification

Layer 1 always runs. It works entirely from the text in the ticket — no internet calls, no models. It processes each ticket through four checks in priority order.

#### Step 1: Government / Authorized Scanner Detection (highest priority)

If the ticket text mentions a known authorized scanner — CISA/DHS CyHy, Shadowserver, Censys, Rapid7, Qualys, BinaryEdge, Stretchoid, Nessus/Tenable, NetSPI, Onyphe, or LeakIX — the ticket is immediately classified as `benign_true_positive` with `threat_type=vulnerability_scan` and the matching actor identified. This check runs before everything else, so even if an ET alert fired on scanner traffic, the ticket will be classified as benign.

#### Step 2: Hard Malicious Disqualifiers

If the **admin note** contains confirmed-threat language, the ticket is immediately classified as `true_positive` with a score of -5. Examples: `recommend block`, `malicious`, `botnet`, `ransomware`, `lateral movement`, `C2 beacon`, `backdoor`, `rootkit`, `cobalt strike`.

If the **ticket summary** contains confirmed-threat keywords (`ET CINS`, `known malicious`, `botnet`, `exploit`, `CVE-`, `malware`, `C2`), the ticket is classified as `true_positive` with a score of -3 if an admin note is present, or -1 if not. Tickets with only a summary keyword and no admin corroboration (-1 score) fall below the -2 threshold needed for the threat database.

> Note: Short words like `rat`, `shell`, and `worm` are matched using word boundaries (e.g., `\brat\b`) to avoid false matches on words like "corroboration" or "nutshell".

#### Step 3: ET Category Parsing

If the summary contains a Suricata/ET rule prefix (`ET SCAN`, `ET EXPLOIT`, `ET TROJAN`, etc.), the ticket is classified as `true_positive` with the matching threat type — unless an admin note says otherwise.

**ET confidence tiers** — not all ET categories are equally reliable as threat signals:

| Tier | Categories | Base score | Rationale |
|---|---|---|---|
| **High** | `ET DROP`, `ET CINS`, `ET COMPROMISED`, `ET TROJAN`, `ET MALWARE`, `ET MOBILE_MALWARE`, `ET PHISHING`, `ET SPAM` | -3 | Explicit blocklist membership or confirmed malware families — reliable even without admin corroboration |
| **Medium** | `ET SCAN`, `ET EXPLOIT`, `ET ATTACK_RESPONSE`, `ET WEB_SERVER`, `ET WEB_CLIENT`, `ET DDOS`, `ET DOS`, `ET CURRENT_EVENTS` | -2 | Active attack/scan patterns — reliable, but admin note adds confidence |
| **Low** | `ET INFO`, `ET POLICY`, `ET HUNTING`, `ET TOR`, `ET P2P`, `ET DNS` | -1 | Informational/policy categories that fire on routine traffic frequently — require admin note to enter the threat database |

If an admin note is present and does not contain benign language, the score is boosted one further point (e.g., a medium-confidence ET ticket with an admin note scores -3 instead of -2).

**Benign override:** If an ET category is matched but the admin note contains a benign keyword (`false positive`, `benign`, `whitelisted`, `expected traffic`, etc.), the ticket is overridden to `false_positive`. This catches tickets where Suricata fired correctly but the analyst determined the traffic was authorized.

#### Step 4: Score Accumulation (for tickets that reach this point)

Tickets that didn't match any of the above checks are scored by accumulating signals from multiple sources. Each signal adds or subtracts from the score:

**Signals from admin notes:**

| Signal | Score | Examples |
|---|---|---|
| FP/benign keyword | +3 | `false positive`, `benign`, `legitimate`, `no indicators of compromise`, `not successful`, `no threat`, `pen test`, `scheduled scan`, `authorized` |
| Known-good infrastructure mention | +1 | `CDN`, `Cloudflare`, `Google DNS`, `known scanner`, `AWS`, `Azure`, `monitoring` |
| GreyNoise classification = benign | +2 | Parsed from copy-pasted enrichment output in the note |
| GreyNoise classification = malicious | −2 | Parsed from copy-pasted enrichment output |
| AbuseIPDB confidence ≥ 80% | −2 | Parsed from `Confidence of Abuse: 87%` style lines in notes |
| AbuseIPDB confidence ≤ 10% | +1 | Low abuse score is a mild benign signal |

**Signals from the ticket fields:**

| Signal | Score | Effect on disposition |
|---|---|---|
| Resolution = `not a bug` | +3 | → `false_positive` |
| Resolution = `unable to duplicate` | +2 | Stays `undetermined` (traffic didn't recur; inconclusive) |
| Summary contains FP keyword (`FP Traffic:`, `All Attempts Blocked`, `Possible False Positive`) | +2 | → `false_positive` |
| AbuseIPDB confidence ≥ 90% in description or notes | −3 | → `true_positive` (`blocklist_hit`) |
| GreyNoise classification = benign in description | +2 | → `false_positive` |

A ticket reaching a **score > 0** with no disqualifying malicious signal contributes its IPs to the FP candidate list.

---

### Layer 2: Pattern-Based Auto-Classification (optional)

Layer 2 only activates for tickets that Layer 1 left as `undetermined` — meaning no clear signal was found in the rules.

**What it does in plain terms:** It reads the patterns in all the tickets that Layer 1 *did* classify confidently, and learns what language tends to appear in FP tickets versus confirmed threat tickets. When it sees a new unclassified ticket, it compares its text against those learned patterns and makes a prediction.

**Technical details:** The model converts ticket text (summary, description, notes) into a numerical representation (TF-IDF — essentially a weighted word frequency count), then uses a linear classifier (LinearSVC) to predict the disposition. Unigrams and bigrams are used (single words and two-word phrases), with common English stop words removed.

**Training data:** The model trains on all tickets where Layer 1 produced a high-confidence result (|score| ≥ 2). Labels with fewer than 5 examples are excluded. At least 50 total training examples are required; training is skipped silently if the index is too small.

**Why it only predicts FP and benign — not threats:** The training data is heavily skewed toward `true_positive` (~92% of tickets are confirmed threats). If the model were allowed to predict all four classes, it would default to `true_positive` for almost any ambiguous ticket — not useful. Rules already handle threat detection well. The ML layer adds value specifically by catching FP and benign patterns that weren't covered by the keyword lists. A threat prediction from Layer 2 is therefore never accepted; the ticket stays `undetermined` if ML would predict it as a threat.

**Confidence threshold:** The model must be at least 30% confident in its prediction (based on the classifier's internal decision margin). Below that, the prediction is discarded and the ticket stays `undetermined`.

**Persistence:** The trained model is saved to `data/tickets/classifier_model.joblib`. It is loaded lazily on first use and cached in memory for subsequent calls. Models trained from an older version of the code (with different label names) are automatically rejected to prevent stale predictions.

**Installing the ML dependency:**

```bash
uv add -r src/mantis/ticket_enrichment/requirements.txt
```

If `scikit-learn` is not installed, Layer 2 is silently skipped and everything else works as normal.

---

### CLI Flags

| Flag | Effect |
|---|---|
| `--classify-stats` | Print disposition/threat_type/actor breakdown after indexing |
| `--retrain` | Force retrain ML classifier from current index |
| `--use-ml` | Enable ML predictions (Layer 2) for FP/threat generation |
| `--from-index` | Reprocess existing index without API fetch |

### Programmatic Usage

```python
from src.mantis.ticket_enrichment import (
    classify, classify_rules, train_model,
    Disposition, ThreatType, Actor,
)

# Layer 1 only (no dependencies)
result = classify_rules(ticket)

# Full pipeline (Layer 1 + Layer 2 if model available)
result = classify(ticket, use_ml=True)

# result.disposition  → Disposition.TRUE_POSITIVE / FALSE_POSITIVE / etc.
# result.threat_type  → ThreatType.PORT_SCAN / ThreatType.MALWARE / None
# result.actor        → Actor.CISA_CYHY / Actor.CENSYS / None
# result.score        → confidence (int for rules, 0-1 for ML)
# result.method       → "rule" or "ml"
# result.signals      → ["et_category: ET SCAN", "admin_note: 'benign'"]

# Check disposition
if result.disposition == Disposition.TRUE_POSITIVE:
    print("confirmed threat, threat_type:", result.threat_type)
elif result.disposition == Disposition.BENIGN_TRUE_POSITIVE:
    print("authorized scanner, actor:", result.actor)

# Train ML model (saves to data/tickets/classifier_model.joblib)
train_model(tickets)
```

---

## mantis_search.py — Searching for Tickets

### CLI usage

```bash
# Search by IP
python src/mantis/mantis_search.py --query 198.51.100.22

# Search by keyword
python src/mantis/mantis_search.py --query "ET SCAN Nmap"

# Filter to a specific project (municipality/organization)
python src/mantis/mantis_search.py --query 198.51.100.22 --city example-city
```

### Search priority

The script always runs all three sources and merges results. Live API results take precedence over the offline index for the same ticket ID.

```
1. Offline index (data/tickets/tickets_index.json)  — instant, full history
2. REST API live search                             — recent tickets, full fields
3. Web scraping fallback                            — full-text including notes
```

If the index doesn't exist yet (first run before indexing), the CLI will still work via the live API — it just won't have historical coverage beyond the most recent pages.

### Output

The CLI table includes handler, severity, and note count columns. Admin notes (★) appear as dim preview rows directly beneath the ticket they belong to:

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

### Sensor-aware project scoping

When called from within the CLI interactive loop (`[m]` action) or the web UI, the search automatically scopes to the project matching the sensor that captured the record. For example, a connection logged by a sensor named `hedgehog-example-city` will scope the Mantis search to the `example-city` project. This works even when the analyst is viewing an "all sensors" overview — the scoping is driven by the individual record, not the global filter.

---

## Web UI Integration

Mantis lookup is available in the record detail panel (the right-side drawer). Click any IP button to search for tickets referencing that address. The panel shows:

- Ticket status and severity badges
- Handler name (the assigned SOC lead)
- Note count with admin note count highlighted
- Admin note callouts — full text up to 300 characters
- Link pills to Kibana saved searches and threat intel services referenced in the ticket

The sensor from the expanded record is automatically forwarded to the search, so results are always scoped to the correct project.

---

## Required Environment Variables

```bash
MANTIS_API_URL=https://mantis.example.internal   # base URL, no trailing slash
MANTIS_API_TOKEN=<your API token>                 # for REST API access
PISCES_USERNAME=<username>                        # for web scraping fallback
PISCES_PASSWORD=<password>                        # for web scraping fallback
```

`MANTIS_API_TOKEN` is required for `mantis_index.py` and the primary search path. The scraping fallback only activates if the REST API returns no results.

---

## Typical Workflows

### Shift start — refresh the index

```bash
python src/mantis/mantis_index.py
# → data/tickets/tickets_index.json  (full history)
# → data/tickets/fp_ips.txt          (FP candidates)
```

### Investigate an IP seen in alerts

```
CLI [m] action on any alert → scoped Mantis results appear inline
```

Or directly:

```bash
python src/mantis/mantis_search.py --query 198.51.100.22
```

Look for:
- **Resolved/closed** tickets → this IP has been investigated; check the admin notes for the verdict
- **Open/acknowledged** tickets → a ticket exists; check who the handler is before creating a duplicate
- **No results** → no prior history; consider enriching the IP and opening a ticket manually in MantisBT

### Review FP candidates after indexing

```bash
# See what was flagged
cat data/tickets/fp_ips.txt

# Spot-check one
python src/mantis/mantis_search.py --query 203.0.113.5
# Look at the ticket(s) — what was the resolution? Admin note verdict?

# If confirmed benign, create a filter
python src/querier/opensearch_querier.py --log-type conn
# → select the record → [f] false positive
```
