# MCP Servers

PISCES exposes three MCP (Model Context Protocol) servers that let an AI assistant query the
same backends used by the CLI and web UI.  Each server is a thin adapter — no logic is
duplicated from the source modules.

| Server | Path | Tools | Purpose |
|---|---|---|---|
| `opensearch` | `mcp/opensearch/` | 16 | Zeek/OpenSearch protocol logs, pivot tools, utilities |
| `mantis` | `mcp/mantis/` | 2 | MantisBT ticket search |
| `enrichment` | `mcp/enrichment/` | 2 | IP threat intelligence and org lookup — no OpenSearch required |

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
| `PISCES_USERNAME` | opensearch | OpenSearch HTTP basic auth |
| `PISCES_PASSWORD` | opensearch | OpenSearch HTTP basic auth |
| `OPENSEARCH_URL` | opensearch | Malcolm/OpenSearch base URL (e.g. `https://opensearch.example.com`) |
| `MANTIS_API_URL` | mantis | MantisBT instance base URL |
| `MANTIS_API_TOKEN` | mantis | MantisBT REST API token |
| `GREYNOISE_API_KEY` | opensearch, enrichment (optional) | GreyNoise enrichment |
| `ABUSEIPDB_API_KEY` | opensearch, enrichment (optional) | AbuseIPDB enrichment |
| `SHODAN_API_KEY` | opensearch, enrichment (optional) | Shodan enrichment |
| `VIRUSTOTAL_API_KEY` | opensearch, enrichment (optional) | VirusTotal enrichment |

The `/api/console/proxy` endpoint path is appended automatically by the code — set only the base URL for `OPENSEARCH_URL`.

---

## Running locally with the MCP Inspector

The Inspector is a browser-based UI for calling tools interactively — useful for testing before
wiring up a client.

```bash
# OpenSearch server (16 tools)
PISCES_USERNAME=x PISCES_PASSWORD=y OPENSEARCH_URL=https://... mcp dev mcp/opensearch/server.py

# Mantis server (2 tools)
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
| `search_alerts` | Search Suricata alerts by time range, severity, and filters |

**Utilities:**

| Tool | Description |
|---|---|
| `list_sensors` | List Malcolm/Zeek sensors active in the given time window |
| `get_notice_summary` | Top Zeek Notice types by frequency |
| `raw_opensearch_search` | Send a raw ES DSL query to OpenSearch |

---

### mantis (2 tools)

| Tool | Description |
|---|---|
| `search_tickets` | Search MantisBT by IP, keyword, or phrase |
| `get_ticket` | Fetch a single issue by numeric ID |

---

### enrichment (2 tools)

Standalone threat intelligence server — requires no OpenSearch connection.
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
