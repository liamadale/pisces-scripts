# MCP Servers

PISCES exposes three MCP (Model Context Protocol) servers that let an AI assistant query the
same backends used by the CLI and web UI.  Each server is a thin adapter — no logic is
duplicated from the source modules.

| Server | Path | Tools | Purpose |
|---|---|---|---|
| `opensearch` | `mcp/opensearch/` | 16 | Zeek/OpenSearch protocol logs, Suricata alerts, pivot tools, utilities |
| `kibana` | `mcp/kibana/` | 4 | Suricata/Kibana alerts with full parameter surface + aggregation tools |
| `mantis` | `mcp/mantis/` | 4 | MantisBT ticket search and creation |
| `enrichment` | `mcp/enrichment/` | 2 | IP threat intelligence and org lookup — no OpenSearch or Kibana required |

---

## Prerequisites

```bash
# Activate the project virtualenv
source .venv/bin/activate

# Install project + MCP dependencies
pip install -r requirements.txt -r mcp/requirements.txt

# Copy the example env file and fill in credentials
cp .env.example .env
```

Credentials required by each server:

| Variable | Required by | Purpose |
|---|---|---|
| `PISCES_USERNAME` | opensearch, kibana | OpenSearch / Kibana HTTP basic auth |
| `PISCES_PASSWORD` | opensearch, kibana | OpenSearch / Kibana HTTP basic auth |
| `OPENSEARCH_URL` | opensearch | Malcolm/OpenSearch base URL (e.g. `https://opensearch.example.com`) |
| `KIBANA_URL` | kibana | Kibana base URL (e.g. `https://kibana.example.com`) |
| `MANTIS_API_URL` | mantis | MantisBT instance base URL |
| `MANTIS_API_TOKEN` | mantis | MantisBT REST API token |
| `GREYNOISE_API_KEY` | opensearch, enrichment (optional) | GreyNoise enrichment |
| `ABUSEIPDB_API_KEY` | opensearch, enrichment (optional) | AbuseIPDB enrichment |
| `SHODAN_API_KEY` | opensearch, enrichment (optional) | Shodan enrichment |
| `VIRUSTOTAL_API_KEY` | opensearch, enrichment (optional) | VirusTotal enrichment |

The `/api/console/proxy` endpoint path is appended automatically by the code — set only the base URL for `OPENSEARCH_URL` and `KIBANA_URL`.

---

## Running locally with the MCP Inspector

The Inspector is a browser-based UI for calling tools interactively — useful for testing before
wiring up a client.

```bash
# OpenSearch server (18 tools)
PISCES_USERNAME=x PISCES_PASSWORD=y OPENSEARCH_URL=https://... mcp dev mcp/opensearch/server.py

# Kibana server (4 tools)
PISCES_USERNAME=x PISCES_PASSWORD=y KIBANA_URL=https://... mcp dev mcp/kibana/server.py

# Mantis server (4 tools)
MANTIS_API_URL=https://mantis.local MANTIS_API_TOKEN=tok mcp dev mcp/mantis/server.py

# Enrichment server (2 tools — API keys all optional)
mcp dev mcp/enrichment/server.py
```

`mcp dev` reads `.env` automatically when the server starts, so if your credentials are already
in `.env` you can omit the inline env prefix.

---

## Connecting a client (Claude Desktop / Claude Code / kiro-cli)

Add each server to your MCP client configuration.  The exact file location varies by client:

- **Claude Desktop** — `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
  or `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- **Claude Code** — `.claude/settings.json` in the project root, or `~/.claude/settings.json`
- **kiro-cli** — `.kiro/settings/mcp.json` in the project root

All servers use the project virtualenv directly — no Docker required.

```json
{
  "mcpServers": {
    "opensearch": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/opensearch/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "PISCES_USERNAME": "your-username",
        "PISCES_PASSWORD": "your-password",
        "OPENSEARCH_URL": "https://your-opensearch-host"
      }
    },
    "kibana": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/kibana/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "PISCES_USERNAME": "your-username",
        "PISCES_PASSWORD": "your-password",
        "KIBANA_URL": "https://your-kibana-host"
      }
    },
    "mantis": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/mantis/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "MANTIS_API_URL": "https://mantis.local",
        "MANTIS_API_TOKEN": "your-token"
      }
    },
    "enrichment": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/enrichment/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "GREYNOISE_API_KEY": "your-key",
        "ABUSEIPDB_API_KEY": "your-key",
        "SHODAN_API_KEY": "your-key",
        "VIRUSTOTAL_API_KEY": "your-key"
      }
    }
  }
}
```

---

## Tool reference

### opensearch (16 tools)

**Zeek protocol logs** — each has `time_range`, `sensor`, `limit`, `public_only`, `src_ip`,
`dest_ip`, `direction`, `no_filters` plus protocol-specific parameters:

| Tool | Protocol-specific parameters |
|---|---|
| `search_conn` | — |
| `search_dns` | `dns_query`, `dns_rcode`, `dns_qtype` |
| `search_http` | `http_method`, `http_host`, `http_uri`, `status_code` |
| `search_ssl` | `ssl_sni`, `ssl_invalid_only` |
| `search_smtp` | `smtp_mail_from`, `smtp_rcpt_to`, `smtp_subject` |
| `search_rdp` | `rdp_result`, `rdp_cookie` |
| `search_smb` | `smb_share`, `smb_action` |
| `search_ssh` | `ssh_failed_only`, `ssh_auth_result` |
| `search_notice` | `notice_note` |
| `search_weird` | `weird_name` |

**Pivot and alert tools:**

| Tool | Description |
|---|---|
| `pivot_ip` | Run all 10 Zeek queries in parallel for a single IP |
| `pivot_alerts` | Check whether an IP has triggered Suricata alerts |
| `search_alerts` | Search Suricata alerts (no `cities` parameter — use the kibana server for that) |

**Utilities:**

| Tool | Description |
|---|---|
| `list_sensors` | List Malcolm/Zeek sensors active in the given time window |
| `get_notice_summary` | Top Zeek Notice types by frequency |
| `raw_opensearch_search` | Send a raw ES DSL query to OpenSearch |

---

### kibana (4 tools)

Exposes the full Kibana/Suricata parameter surface including `cities` filtering and aggregation
endpoints not available in the opensearch server.

| Tool | Description |
|---|---|
| `search_alerts` | Search deduplicated Suricata alerts — supports `cities`, `dest_ip`, all severity/signature filters |
| `list_cities` | Terms aggregation on `clientID` — returns city names and alert counts |
| `get_signature_summary` | Top Suricata signatures by frequency for a given time window and severity |
| `raw_kibana_search` | Send a raw ES DSL query body directly to Kibana |

Key parameters for `search_alerts`:

| Parameter | Default | Notes |
|---|---|---|
| `time_range` | `now-24h` | Elasticsearch date math |
| `severity` | `3` | Max severity to include (1=critical, 3=low) |
| `cities` | `"all"` | Comma-separated `clientID` values, or `"all"` |
| `src_ip` | — | Post-filter by source IP |
| `dest_ip` | — | Post-filter by destination IP |
| `signature` | — | Substring match on `alert.signature` |
| `public_only` | `false` | Exclude RFC-1918 source IPs |

---

### mantis (4 tools)

| Tool | Description |
|---|---|
| `search_tickets` | Search MantisBT by IP, keyword, or phrase |
| `get_ticket` | Fetch a single issue by numeric ID |
| `create_ticket` | Create a ticket with summary, description, severity, priority |
| `create_ticket_from_alert` | Create a ticket pre-filled from a Suricata alert JSON dict |

---

### enrichment (2 tools)

Standalone threat intelligence server — requires no OpenSearch or Kibana connection.
All API keys are optional; missing keys simply skip that service.

| Tool | Description |
|---|---|
| `enrich_ip` | Full pipeline: GreyNoise → AbuseIPDB → Shodan → VirusTotal + org lookup + reference URLs |
| `lookup_ip_org` | CIDR-based ownership lookup (cloud/CDN/scanner) — no API key required |

---

## Response format

All tools return a JSON string.  On success:

```json
{"status": "ok", "data": { ... }}
```

On error:

```json
{"status": "error", "message": "description of what went wrong"}
```

This consistent envelope means you can always check `status` before reading `data`, and error
messages are surfaced directly to the LLM rather than causing an exception.
