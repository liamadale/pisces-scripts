# Getting Started

This guide walks you through installing the toolkit on Ubuntu, adding your credentials,
and launching the web UI for the first time.

---

## Prerequisites

- Ubuntu 24.04 or 26.04 with OpenVPN connected to the cyber range network
- A terminal
- Your PISCES credentials and API keys

Don't have a VM set up yet? See the [VM Setup guide](vm-setup.md) first.

---

## 1. Install uv

`uv` is the package manager this project uses. Install it with:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then restart your terminal (or run `source ~/.bashrc`) so the `uv` command is available.

---

## 2. Clone the repository

```bash
git clone https://github.com/liamadale/pisces-scripts.git
cd pisces-scripts
```

---

## 3. Install dependencies

```bash
uv sync
```

This installs everything the toolkit needs. You only need to do this once.

---

## 4. Add your credentials

Copy the example credentials file:

```bash
cp .env.example .env
```

Open `.env` in a text editor and fill in your credentials:

```
# Malcolm / OpenSearch access
PISCES_USERNAME=your-username
PISCES_PASSWORD=your-password
OPENSEARCH_URL=https://opensearch-instance

# Threat intelligence — add whichever API keys you have
# Any service without a key is simply skipped
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
VIRUSTOTAL_API_KEY=

# Mantis ticketing
MANTIS_API_URL=https://mantis-instance
MANTIS_API_TOKEN=your-token
```

---

## 5. Launch the web UI

```bash
uv run run_all.py
```

Then open your browser and navigate to:

- **Accessing the WebUI from a VM:** http://\<your-vm-ip\>:5000

You should see the hub landing page with links to all four apps.

---

## 6. Build the Mantis index

The Mantis indexer pulls the full PISCES ticket dataset from the API into a local
index. This is what powers instant ticket search and provides the input for the threat
model. Run it before your first session:

```bash
uv run src/mantis/mantis_index.py
```

A progress bar shows pages being fetched. When it finishes, the index is written to
`data/tickets/indexed/tickets_index.json`.

**Rebuild the index at the start of each shift** to pick up tickets created since your
last run. Any ticket not yet in the local index is still reachable via a live API
fallback during search.

---

## 7. Run the threat model generator

Once the index exists, run the threat model generator to classify every ticket and
produce the IP registries that power the Mantis web app:

```bash
uv run src/mantis/mantis_threat_model.py
```

This reads `tickets_index.json` and writes five files to `data/tickets/enriched/`:

| File | What it contains |
|---|---|
| `malicious_ips.json` | Confirmed threat IPs with attack types, CVEs, blocklist hits |
| `false_positive_ips.json` | IPs flagged as likely false positives across ticket history |
| `known_infra_ips.json` | Known infrastructure IPs (CDN, cloud, scanners) |
| `dns_resolver_ips.json` | Known public DNS resolver IPs |
| `undetermined_ips.json` | IPs the classifier couldn't confidently resolve |

To also print a classification breakdown after the run:

```bash
uv run src/mantis/mantis_threat_model.py --classify-stats
```

**Run the threat model after every index rebuild** — the web app reads directly from
these files, so stale output means a stale dashboard.

See [mantis-threat-model.md](mantis-threat-model.md) for the full flag reference and
how to use API enrichment for undetermined IPs.

---

## 8. Set up the MCP servers (AI assistant integration)

PISCES includes three MCP servers that connect your AI assistant — Claude Code, Claude
Desktop, or kiro-cli — directly to the same backends as the web UI. Once configured,
you can ask your assistant to investigate IPs, search tickets, and run enrichment
without leaving your conversation.

See the **[MCP Getting Started guide](getting-started-mcp.md)** for setup instructions.

---

## What's next

| | |
|---|---|
| [MCP Servers](getting-started-mcp.md) | Connect Claude Code or Claude Desktop to the PISCES backends |
| [Web UI Workflow](workflow.md) | How to triage alerts, enrich IPs, create false positive filters, and link findings to Mantis tickets using the browser-based UI |
| [CLI Workflow](cli-workflow.md) | Terminal-based querier walkthrough |
| [False Positive Filters](filter-schema.md) | How filters work and how to manage them |
| [Mantis Integration](mantis.md) | More on ticket indexing and search |
| [Advanced Usage](advanced-usage.md) | Full CLI flag reference if you want to go beyond the web UI |
