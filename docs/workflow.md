# Analyst Workflow

A typical session from launch to resolution. Two querier workflows are documented below: the Malcolm/Zeek OpenSearch querier (primary) and the Kibana/Suricata querier.

---

## Malcolm/Zeek Workflow (`opensearch_querier.py`)

### 1. Launch the querier

```bash
.venv/bin/python src/querier/opensearch_querier.py --log-type conn --public-only --time-range now-24h
```

Common flags:

| Flag | Default | Purpose |
|---|---|---|
| `--log-type` | required | Protocol log: conn, dns, http, ssl, smtp, rdp, smb, ssh, notice, weird |
| `--time-range` | `now-24h` | OpenSearch date-math range |
| `--sensor` | `all` | Comma-separated sensor hostname(s) |
| `--public-only` | off | Exclude RFC 1918 source IPs |
| `--src-ip` | — | Filter to a specific source IP |
| `--limit` | `100` | Max raw hits before deduplication |

The tool loads all enabled YAML filters, queries Malcolm's OpenSearch index, deduplicates by the module's key, and prints a protocol-specific table. The interactive loop actions (`[e]nrich`, `[f]alse positive`, `[m]antis search`, `[t]icket`) are identical to the Kibana workflow below.

---

## Kibana/Suricata Workflow (`kibana_querier.py`)

### 1. Launch the querier

```bash
.venv/bin/python src/querier/kibana_querier.py --time-range now-24h --severity 2 --public-only
```

Common flags:

| Flag | Default | Purpose |
|---|---|---|
| `--time-range` | `now-24h` | Kibana date-math range |
| `--severity` | `3` | Max severity to include (1=high, 3=low) |
| `--cities` | `all` | Comma-separated city/clientID filter |
| `--public-only` | off | Exclude RFC 1918 source IPs |
| `--signature` | — | Filter to alerts matching a phrase |
| `--limit` | `50` | Max raw ES hits before deduplication |

The tool loads all enabled YAML filters, queries Kibana, deduplicates by `(src_ip, signature)`, and prints a table:

```
Found 23 unique alert(s) across 50 raw event(s) (sorted by frequency)

 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  #   Timestamp         City          Signature                    Sev  Freq  Src IP
 ────────────────────────────────────────────────────────────────────────────────────
  1   2026-02-22 14:31  <city>        ET SCAN Zmap User-Agent      2    14    185.220.101.45
  2   2026-02-22 13:55  <city>        ET TROJAN Meterpreter         1    8     103.14.8.22
  3   2026-02-22 12:10  <city>        ET SCAN Nmap Scripting        2    3     45.33.32.156
```

---

## 2. Select an alert

At the action prompt, enter the alert number:

```
Action — enter alert # / [r]e-search / [p]rint (CTRL+C to exit):
  > 2
```

Then choose an action:

```
Alert #2: ET TROJAN Meterpreter | 103.14.8.22
  [e]nrich  [f]alse positive  [m]antis search  [t]icket  [s]kip
  Action:
```

---

## 3. Actions

### `[e]` Enrich

Runs the full threat intelligence pipeline:

1. **GreyNoise** — classification (benign / malicious / not found), name, reason
   - If **benign**: offer to create an FP filter, print reference URLs, stop
2. **AbuseIPDB** — confidence score, report count, ISP, domain, usage type
3. **Shodan** — open ports, OS, org, CVEs
4. **VirusTotal** — vendor detection count breakdown
5. **Reference URLs** — always printed for manual review

```
GreyNoise — 103.14.8.22
  Classification   malicious
  Name             TOR Exit Node

AbuseIPDB — 103.14.8.22
  Confidence Score  94%
  Total Reports     512
  ISP               Frantech Solutions
  Usage Type        Data Center/Web Hosting/Transit

Shodan — 103.14.8.22
  Org          Frantech Solutions
  Open Ports   22, 80, 443, 9001, 9030
  Vulns        CVE-2023-38545

VirusTotal — 103.14.8.22
  Malicious    18
  Suspicious   2
  Harmless     51

Reference Links
  GreyNoise    https://viz.greynoise.io/ip/103.14.8.22
  AbuseIPDB    https://www.abuseipdb.com/check/103.14.8.22
  Shodan       https://www.shodan.io/search?query=103.14.8.22
  VirusTotal   https://www.virustotal.com/gui/ip-address/103.14.8.22
```

### `[f]` False Positive Filter

Opens the interactive filter creator, pre-seeded with the alert's IP and metadata. Prompts for:
- Category and subcategory
- Clause type (`term`, `match_phrase`, `bool`, etc.)
- Optional comment (auto-suggested from GreyNoise enrichment if already run)

The filter is written to the appropriate YAML file immediately. The next `[r]`e-search will pick it up without restarting.

### `[m]` Mantis Search

Searches MantisBT for existing tickets matching the alert's public IPs. Private/RFC 1918 addresses are skipped automatically. Results show ticket ID, summary, status, and last-updated date.

### `[t]` Ticket

Opens the interactive ticket submission flow, pre-seeded with the alert's raw event data.

### `[s]` Skip

No action taken. Returns to the prompt. The last-alert hint will not update.

---

## 4. Prompt navigation

| Input | Effect |
|---|---|
| `<number>` | Select alert by row number |
| `r` | Re-search Kibana with new or modified parameters (reloads filters from disk) |
| `p` | Reprint the alert table without querying Kibana |
| `CTRL+C` | Confirm-exit prompt (press again to quit, Enter to continue) |

The dim hint above each prompt shows the last alert you acted on:

```
↩  Last: #2 ET TROJAN Meterpreter | 103.14.8.22

Action — enter alert # / [r]e-search / [p]rint (CTRL+C to exit):
  >
```

---

## 5. Typical session patterns

### Triage a batch, create tickets for the high-severity hits

```
> 1  →  [e]  →  malicious/high score  →  [t]  →  submit ticket
> 2  →  [e]  →  malicious             →  [t]  →  submit ticket
> 3  →  [e]  →  benign (GreyNoise)    →  add to FP filter
> r  →  re-search to confirm filter took effect
```

### Mid-session filter a recurring noisy scanner

```
> 7  →  [e]  →  GreyNoise: benign, Censys
       →  [f]  →  category: ips / known_scanners
                  comment: Censys (auto-suggested)
> r  →  re-search — alert #7 is gone
```

### Quickly check if a ticket already exists before creating a new one

```
> 4  →  [m]  →  Mantis results show open ticket #1842
       →  [s]  →  skip, ticket already exists
```
