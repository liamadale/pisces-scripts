# Getting Started — MCP Servers

PISCES exposes three MCP (Model Context Protocol) servers that let an AI assistant
query the same backends used by the web UI and CLI. Ask it to investigate an IP,
search tickets, pivot across protocols, or run enrichment, all without leaving your
conversation.

| Server | Tools | What it gives your AI assistant |
|---|---|---|
| `opensearch` | 16 | Query all Zeek protocol logs, pivot on IPs, search alerts |
| `mantis` | 2 | Search the PISCES ticket dataset by IP, keyword, or signature |
| `enrichment` | 2 | IP threat intelligence and org lookup — no OpenSearch required |

---

## Prerequisites

Complete the [Getting Started guide](getting-started.md) first — the MCP servers use
the same credentials and virtualenv.

---

## 1. Install MCP dependencies

The MCP servers require an additional set of dependencies not included in the base
install:

```bash
uv sync --extra mcp
```

---

## 2. Configure your AI client

Replace `/path/to/pisces-scripts` with the absolute path to your clone throughout.
Any enrichment API key left blank is simply skipped. You can include only the servers
you need — all three are independent.

---

### Claude Code

Config file: `~/.claude/settings.json` (global) or `.claude/settings.json` in the
project root (project-scoped).

```json
{
  "mcpServers": {
    "pisces-opensearch": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/opensearch/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "PISCES_USERNAME": "your-username",
        "PISCES_PASSWORD": "your-password",
        "OPENSEARCH_URL": "https://your-opensearch-host"
      }
    },
    "pisces-mantis": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/mantis/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "MANTIS_API_URL": "https://your-mantis-instance",
        "MANTIS_API_TOKEN": "your-token"
      }
    },
    "pisces-enrichment": {
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

### kiro-cli

Config file: `.kiro/settings/mcp.json` in the project root.

```json
{
  "mcpServers": {
    "pisces-opensearch": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/opensearch/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "PISCES_USERNAME": "your-username",
        "PISCES_PASSWORD": "your-password",
        "OPENSEARCH_URL": "https://your-opensearch-host"
      }
    },
    "pisces-mantis": {
      "command": "/path/to/pisces-scripts/.venv/bin/python",
      "args": ["mcp/mantis/server.py"],
      "cwd": "/path/to/pisces-scripts",
      "env": {
        "MANTIS_API_URL": "https://your-mantis-instance",
        "MANTIS_API_TOKEN": "your-token"
      }
    },
    "pisces-enrichment": {
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

### Other clients

The PISCES MCP servers will work with any client that supports the MCP standard. Two
others worth noting:

- **gemini-cli** — Google's Gemini CLI supports MCP servers. See the
  [gemini-cli MCP documentation](https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/mcp-server.md)
  for configuration details.
- **codex-cli** — OpenAI's Codex CLI also supports MCP. See the
  [codex-cli configuration documentation](https://github.com/openai/codex/blob/main/docs/config.md)
  for MCP server configuration details.

The server command, args, and env block structure used above is standard across MCP
clients — the config format should transfer directly.

---

## 3. Verify the connection

Restart your client after editing the config. The servers should appear in your
client's tool list. You can test immediately:

```
What Zeek connection logs are there for IP 198.51.100.22 in the last 24 hours?
```

```
Search PISCES tickets for 185.220.101.45
```

```
Enrich 103.14.8.22
```

If a server fails to start, check that:
- The `.venv` path is correct and `uv sync --extra mcp` has been run
- Your credentials in the config block are filled in
- The `cwd` path points to the root of the repository

---

## What's next

See [mcp-servers.md](mcp-servers.md) for the full tool reference — every tool name,
its parameters, and the response format.
