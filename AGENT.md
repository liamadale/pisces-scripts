# PISCES-NW SOC Agent Guide

## 1. Mission

PISCES-NW is a student SOC monitoring 19+ Washington State municipalities via Zeek (Malcolm) and
Suricata IDS. Your job is to surface leads from Kibana/OpenSearch, enrich suspicious IPs, and write
investigation reports to `reports/` for human review. Work alert-first: find Suricata alerts →
identify suspicious IPs → cross-correlate Zeek logs → enrich → write report or close as FP.

**Do not file Mantis tickets.** Write a report file and let a human decide whether to escalate.

---

## 2. Environment Architecture — Two Completely Separate Networks

**CRITICAL**: Kibana and OpenSearch monitor **different physical networks**. An IP seen in one
will essentially never appear in the other. Never cross-query between them for the same IP.

| | Kibana (Suricata) | OpenSearch / Malcolm (Zeek) |
|---|---|---|
| Network | Washington municipality infrastructure | Cyber range / lab environment |
| Data | Suricata IDS alerts | Zeek behavioral logs (10 protocols) |
| Index | `suricata*` | `arkime_sessions3-*` |
| Scope filter | `cities` (clientID) | `sensor` (sensor hostname) |

**Shared tools — valid regardless of network:**
- `@enrichment` — external IP reputation (no backend required)
- `@mantis` — read-only ticket lookup (search/get only; do not create tickets)

---

## 3. Two Investigation Tracks

### Track A — Kibana (Washington Municipal Networks)

1. Surface leads: `@kibana search_alerts` — filter by city + `severity=2`
2. Identify suspicious IPs from alert table
3. Org check: `@enrichment lookup_ip_org` (free, instant)
4. Enrich if still suspicious: `@enrichment enrich_ip`
5. Check for existing ticket: `@mantis search_tickets`
6. Write report to `reports/` — see Section 9 for format and filename convention

### Track B — OpenSearch / Malcolm (Cyber Range)

1. Surface leads: `@opensearch search_notice` / `search_weird` / `get_notice_summary`
2. All-protocol pivot: `@opensearch pivot_ip ip=X.X.X.X`
3. Org check: `@enrichment lookup_ip_org`
4. Enrich if still suspicious: `@enrichment enrich_ip`
5. Protocol deep-dive with specific `search_*` tools as needed
6. Check for existing ticket: `@mantis search_tickets`
7. Write report to `reports/` — see Section 9 for format and filename convention

---

## 4. MCP Tools by Phase

### Surface leads — Kibana track

| Tool | Use |
|---|---|
| `@kibana list_cities` | Discover active municipalities + alert counts |
| `@kibana search_alerts` | Primary triage; params: `cities`, `severity`, `signature`, `src_ip`, `time_range` |
| `@kibana get_signature_summary` | Signature frequency heatmap — overview before diving in |
| `@kibana raw_kibana_search` | Raw ES DSL for custom aggregations |

### Surface leads — OpenSearch track

| Tool | Use |
|---|---|
| `@opensearch list_sensors` | Discover active sensors + record counts |
| `@opensearch search_notice` | High-signal Zeek policy alerts |
| `@opensearch search_weird` | Protocol anomalies |
| `@opensearch get_notice_summary` | Zeek notice type frequency |
| `@opensearch search_alerts` | Suricata alerts (range env; no `cities` param here) |

### Investigate an IP (both tracks)

| Tool | Use |
|---|---|
| `@enrichment lookup_ip_org ip=X` | **Always run first** — CIDR ownership, no API key, instant |
| `@enrichment enrich_ip ip=X` | Full pipeline: GreyNoise → AbuseIPDB → Shodan → VirusTotal |
| `@opensearch pivot_ip ip=X` | All 10 Zeek logs in parallel (range network only) |

**API key conservation**: enrichment keys (GreyNoise, AbuseIPDB, Shodan, VirusTotal) are
rate-limited. Always run `lookup_ip_org` first. Only call `enrich_ip` on IPs that remain
suspicious after the org lookup. Skip entirely for known CDN/scanner/cloud IPs. GreyNoise stops
the pipeline early on benign classification, preserving downstream quota.

### Protocol deep-dive (OpenSearch / range only)

`search_conn`, `search_dns`, `search_http`, `search_ssl`, `search_smtp`, `search_rdp`,
`search_smb`, `search_ssh`, `search_notice`, `search_weird`

Common params: `time_range`, `src_ip`, `dest_ip`, `sensor`, `public_only`, `no_filters`, `limit`

### Mantis lookup — read-only (both tracks)

Do not create tickets. Use Mantis only to check for prior work before writing a report.

| Tool | Use |
|---|---|
| `@mantis search_tickets query="..."` | Check for existing ticket before writing a report |
| `@mantis get_ticket` | Fetch a single ticket by numeric ID for context |

---

## 5. Key Tool Notes

- `cities` param (Kibana only): comma-separated clientID values or `"all"`; not present in OpenSearch tools
- `public_only=true`: exclude RFC-1918 source IPs from results
- `no_filters=true`: bypass local FP YAML filters (use only when investigating a suspected FP)
- `severity`: 1=critical, 2=high, 3=medium; start triage with `severity=2` to catch high+critical
- `raw_opensearch_search` / `raw_kibana_search`: accept raw ES DSL JSON for advanced queries

---

## 6. Monitored Municipalities (clientID values)

`bonney-lake`, `bainbridge`, `yelm`, `union-gap`, `college-place`, `benton`, `colville`,
`spokanevalley`, `poulsbo`

Use `@kibana list_cities` to discover all active cities and their current alert counts.

---

## 7. Common False Positives

Verify context before escalating. Key patterns:

| Category | Signal | Action |
|---|---|---|
| **Windows connectivity** | `ET INFO Terse Request for .txt - Likely Hostile` → dest 13.107.4.52 | Benign Windows check |
| **CDN traffic** | High volume from Akamai (23.x/104.x), Fastly, Cloudflare, Edgecast | Run `lookup_ip_org`; benign if known CDN |
| **Known scanners** | Shodan, Censys, university research IPs | Verify via `enrich_ip`; suppress if confirmed |
| **P2P misidentification** | `ET P2P Edonkey Connect Request` from internal ranges | Verify no actual P2P app; often misclassified |
| **Dropbox/cloud storage** | `ET POLICY Dropbox.com Offsite File Backup in Use` | Policy violation, not a security threat |
| **RMM tools** | `ET INFO Observed RMM Domain in DNS Lookup`, `ET INFO Observed RMM Domain in TLS SNI`, `ET POLICY Observed DNS Query for Suspicious TLD (.management)` — domains: n-able.com, connectwise.com, datto.com, beanywhere.com | Verify with municipality IT; benign if authorized |
| **DynDNS** | `ET POLICY DNS Query to DynDNS Domain *.ddns .net`, `*.redirectme.net` | Verify authorization; may be legitimate remote access |
| **STUN/VOIP** | `ET INFO Session Traversal Utilities for NAT (STUN Binding Request)` | Benign for known VOIP services |
| **SpamHaus blocks** | Connection attempts from SpamHaus-listed IPs | Firewall blocking correctly; benign |
| **Zero-byte port scans** | Multiple connections, 0 bytes transferred | Rejected by firewall; benign |
| **Suricata engine noise** | `SURICATA STREAM *`, `SURICATA AF-PACKET *` | Internal engine messages; not real alerts |
| **Browser extensions** | DNS queries for `.to` TLD, key-cdn.printfriendly.com | Verify extension legitimacy |

**FP check order**: org lookup → bytes=0 check → known CDN/scanner match → signature pattern → verify with municipality

---

## 8. Quick Reference

**Time ranges**: `now-1h`, `now-6h`, `now-24h`, `now-7d`, `now-30d`; ISO 8601 for ticket timestamps

**Suricata index**: `suricata*` | **Zeek index**: `arkime_sessions3-*`

**Severity scale**: 1=critical, 2=high, 3=medium (default triage: `severity=2`)

**Response format**: All tools return `{"status": "ok", "data": {...}}` or `{"status": "error", "message": "..."}` — always check `status` before reading `data`

**Standard triage session**:
```
list_cities → search_alerts (severity=2) → lookup_ip_org →
  if benign org: close/skip (no report needed)
  if suspicious: enrich_ip → search_tickets →
    write report to reports/YYYY-MM-DD_<city>_<ip>_<brief>.md
```

---

## 9. Report Format

Write all investigation findings to `reports/` as markdown files. A human reviewer will decide
whether to escalate to Mantis. See `reports/` for worked examples.

**Filename**: `YYYY-MM-DD_<city-or-sensor>_<ip>_<brief-slug>.md`
- Escalation example: `2026-02-25_bonney-lake_129.212.184.16_apache-exploit.md`
- False positive example: `2026-02-24_range_35.9.37.146_msu-mirror-fp.md`

**Status line** (top of file): `ESCALATE`, `FALSE POSITIVE`, or `MONITOR`

---

### Template

```markdown
# Summary

<STATUS> - <One-line title matching Mantis summary format>
<IP> (<Org>) targeting <dest IP> (<city/sensor>) — <brief threat description>

---

# Description

## Analyst Notes

<2-4 paragraphs: what triggered the alert, enrichment findings, traffic context,
confidence assessment, MITRE ATT&CK mapping if applicable>

## Packet Snippet

<City/Sensor> Sensor:
- source ip: <ip>
- source org: <org (ASN, country)>
- destination ip: <ip>
- destination port: <port> (<protocol>)
- application protocol: <proto>
- timestamp: <ISO 8601>
- <protocol-specific fields: url, method, status, dns query, ssh result, etc.>
- flow: <N packets to server (XKB), N packets to client (XKB)>
- detection: <signature name and ID> (Severity <N>)

<Repeat block for additional sensors/events if relevant>

## Recommendations

IMMEDIATE ACTIONS:
1. <Specific firewall/patching/review action>
2. <Follow-up investigation step>

---

# Steps To Reproduce

Time Range: <ISO 8601 start> → <ISO 8601 end>
Query: <tool + params used, or saved search URL>

---

# Additional Information

GreyNoise   = https://viz.greynoise.io/ip/<ip>
AbuseIPDB   = https://www.abuseipdb.com/check/<ip>
Shodan      = https://www.shodan.io/host/<ip>
VirusTotal  = https://www.virustotal.com/gui/ip-address/<ip>
```

### What to include per status

| Status | Analyst Notes focus | Recommendations |
|---|---|---|
| **ESCALATE** | Enrichment hits, MITRE mapping, multi-sensor confirmation, traffic direction | Block IP, patch/review target, check for successful compromise |
| **MONITOR** | Ambiguous signals, partial enrichment, low-confidence | Re-check in N days, watch for recurrence, verify with municipality |
| **FALSE POSITIVE** | Why it's benign (org, bytes=0, known service) | Add to YAML filter, no escalation |
