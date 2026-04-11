#!/usr/bin/env python3
"""Enrichment MCP Server — IP threat intelligence and org lookup.

2 tools: enrich_ip, lookup_ip_org.

All API keys are optional — missing keys skip that service.

Run locally (MCP Inspector):
    source .venv/bin/activate && pip install -r mcp/requirements.txt
    mcp dev mcp/enrichment/server.py

Connect via client config:
    command: /path/to/.venv/bin/python
    args:    [mcp/enrichment/server.py]
    env:     GREYNOISE_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, VIRUSTOTAL_API_KEY
"""

import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dotenv import load_dotenv

_env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(os.path.abspath(_env_path))

from src.utils.dns import setup_dns

setup_dns()

from mcp.server.fastmcp import FastMCP
from src.enricher.threat_intel import enrich_ip as _enrich_ip
from src.enricher import greynoise, abuseipdb, shodan, virustotal
from src.utils.ip_org import lookup_org

mcp = FastMCP("enrichment")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ok(data) -> str:
    return json.dumps({"status": "ok", "data": data}, default=str)


def _err(msg: str) -> str:
    return json.dumps({"status": "error", "message": msg})


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool()
def enrich_ip(ip: str) -> str:
    """Run the full threat intelligence enrichment pipeline for an IP address.

    Calls in order: GreyNoise → AbuseIPDB → Shodan → VirusTotal (AbuseIPDB/Shodan/VT
    run concurrently).  If GreyNoise classifies the IP as benign, the remaining
    services are skipped.

    Also appends the org lookup result (cloud/CDN/scanner) and reference URLs
    for each service.  All API keys are optional — missing keys skip that service.

    Returns a dict with keys: ip, org, urls, greynoise, abuseipdb, shodan, virustotal.
    """
    try:
        result = _enrich_ip(ip, offer_fp=False)

        # Strip raw sub-keys to keep the response LLM-friendly
        for key in ("greynoise", "abuseipdb", "shodan", "virustotal"):
            if isinstance(result.get(key), dict):
                result[key] = {k: v for k, v in result[key].items() if k != "raw"}

        result["org"] = lookup_org(ip)
        result["urls"] = {
            "greynoise": greynoise.URL.format(ip=ip),
            "abuseipdb": abuseipdb.URL.format(ip=ip),
            "shodan": shodan.URL.format(ip=ip),
            "virustotal": virustotal.URL.format(ip=ip),
        }
        return _ok(result)
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def lookup_ip_org(ip: str) -> str:
    """Look up the organisation, cloud provider, CDN, or scanner that owns an IP.

    Uses bundled CIDR tables (Cloudflare, Fastly, Shodan, Censys, etc.) plus a
    disk-cached copy of AWS/GCP/Azure IP ranges.  No API key required.

    Returns: {name, icon, category} or null for unknown IPs.
    """
    try:
        org = lookup_org(ip)
        return _ok({"ip": ip, "org": org})
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
