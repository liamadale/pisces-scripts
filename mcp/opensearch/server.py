#!/usr/bin/env python3
"""PISCES MCP Server — thin adapter over the existing CLI backend.

All 16 tools are defined here.  No existing source files are modified.

Run locally (MCP Inspector):
    source .venv/bin/activate && pip install mcp[cli]
    PISCES_USERNAME=x PISCES_PASSWORD=y mcp dev mcp/pisces/server.py

Run via Docker:
    docker build -f mcp/pisces/Dockerfile -t pisces-mcp .
    docker run --rm -i -e PISCES_USERNAME -e PISCES_PASSWORD -e OPENSEARCH_URL pisces-mcp
"""

import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# Allow importing project modules when run from the mcp/pisces/ directory or as a
# Docker container with WORKDIR /app.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from dotenv import load_dotenv

# Load credentials before any project import that checks env vars.
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", ".env")
load_dotenv(os.path.abspath(_env_path))

from src.utils.dns import setup_dns
setup_dns()

from mcp.server.fastmcp import FastMCP

from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import run_query, query_opensearch, INDEX
from src.querier.kibana_module import KibanaModule, run_kibana_query
from src.enricher.threat_intel import enrich_ip as _enrich_ip
from src.enricher import greynoise, abuseipdb, shodan, virustotal
from src.utils.ip_org import lookup_org

mcp = FastMCP("pisces")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialise_records(records: list) -> list:
    """Strip _raw keys and convert sets to lists so records are JSON-safe."""
    out = []
    for rec in records:
        r = {k: v for k, v in rec.items() if k != "_raw"}
        if isinstance(r.get("sensors"), set):
            r["sensors"] = sorted(r["sensors"])
        out.append(r)
    return out


def _serialise_alerts(alerts: list) -> list:
    """Same treatment for Kibana alert records."""
    out = []
    for alert in alerts:
        a = {k: v for k, v in alert.items() if k != "_raw"}
        if isinstance(a.get("cities"), set):
            a["cities"] = sorted(a["cities"])
        out.append(a)
    return out


def _ok(data) -> str:
    return json.dumps({"status": "ok", "data": data}, default=str)


def _err(msg: str) -> str:
    return json.dumps({"status": "error", "message": msg})


def _base_params(
    time_range: str,
    sensor: str,
    limit: int,
    public_only: bool,
    src_ip: Optional[str],
    direction: Optional[str],
    no_filters: bool,
) -> dict:
    params: dict = {
        "time_range": time_range,
        "sensor": sensor,
        "limit": limit,
        "public_only": public_only,
        "no_filters": no_filters,
        "raise_on_error": True,
    }
    if src_ip:
        params["src_ip"] = src_ip
    if direction:
        params["direction"] = direction
    return params


def _apply_dest_ip_filter(records: list, dest_ip: Optional[str]) -> list:
    """Post-filter records by destination IP (base.py only natively filters src_ip)."""
    if not dest_ip:
        return records
    return [r for r in records if r.get("dest_ip") == dest_ip]


# ---------------------------------------------------------------------------
# 10 Zeek protocol tools
# ---------------------------------------------------------------------------

@mcp.tool()
def search_conn(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
) -> str:
    """Search Zeek conn (connection) logs from Malcolm/OpenSearch.

    Returns deduplicated connection records sorted by frequency.
    Common fields: src_ip, dest_ip, dest_port, proto, bytes, duration, sensor.
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        records = run_query(MODULES["conn"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_dns(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    dns_query: Optional[str] = None,
    dns_rcode: Optional[str] = None,
    dns_qtype: Optional[str] = None,
) -> str:
    """Search Zeek DNS logs from Malcolm/OpenSearch.

    Args:
        dns_query: Domain name to filter by (substring match).
        dns_rcode: Response code to filter by, e.g. "NXDOMAIN".
        dns_qtype: Query type to filter by, e.g. "A", "MX", "TXT".
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if dns_query:
            params["dns_query"] = dns_query
        if dns_rcode:
            params["rcode"] = dns_rcode
        if dns_qtype:
            params["qtype"] = dns_qtype
        records = run_query(MODULES["dns"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_http(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    http_method: Optional[str] = None,
    http_host: Optional[str] = None,
    http_uri: Optional[str] = None,
    status_code: Optional[int] = None,
) -> str:
    """Search Zeek HTTP logs from Malcolm/OpenSearch.

    Args:
        http_method: HTTP method filter, e.g. "POST", "GET".
        http_host: Virtual host header to filter by.
        http_uri: URI path substring to filter by.
        status_code: HTTP response status code to filter by.
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if http_method:
            params["http_method"] = http_method
        if http_host:
            params["http_host"] = http_host
        if http_uri:
            params["http_uri"] = http_uri
        if status_code is not None:
            params["status_code"] = status_code
        records = run_query(MODULES["http"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_ssl(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    ssl_sni: Optional[str] = None,
    ssl_invalid_only: bool = False,
) -> str:
    """Search Zeek SSL/TLS logs from Malcolm/OpenSearch.

    Args:
        ssl_sni: Server Name Indication hostname to filter by.
        ssl_invalid_only: If True, return only connections with invalid/self-signed certs.
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if ssl_sni:
            params["ssl_sni"] = ssl_sni
        if ssl_invalid_only:
            params["ssl_invalid_only"] = True
        records = run_query(MODULES["ssl"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_smtp(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    smtp_mail_from: Optional[str] = None,
    smtp_rcpt_to: Optional[str] = None,
    smtp_subject: Optional[str] = None,
) -> str:
    """Search Zeek SMTP logs from Malcolm/OpenSearch.

    Args:
        smtp_mail_from: Sender address to filter by.
        smtp_rcpt_to: Recipient address to filter by.
        smtp_subject: Subject line substring to filter by.
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if smtp_mail_from:
            params["smtp_mail_from"] = smtp_mail_from
        if smtp_rcpt_to:
            params["smtp_rcpt_to"] = smtp_rcpt_to
        if smtp_subject:
            params["smtp_subject"] = smtp_subject
        records = run_query(MODULES["smtp"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_rdp(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    rdp_result: Optional[str] = None,
    rdp_cookie: Optional[str] = None,
) -> str:
    """Search Zeek RDP logs from Malcolm/OpenSearch.

    Args:
        rdp_result: RDP result string to filter by, e.g. "encrypted".
        rdp_cookie: RDP cookie/username string to filter by.
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if rdp_result:
            params["rdp_result"] = rdp_result
        if rdp_cookie:
            params["rdp_cookie"] = rdp_cookie
        records = run_query(MODULES["rdp"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_smb(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    smb_share: Optional[str] = None,
    smb_action: Optional[str] = None,
) -> str:
    """Search Zeek SMB logs from Malcolm/OpenSearch.

    Args:
        smb_share: SMB share name to filter by.
        smb_action: SMB action verb to filter by, e.g. "SMB::FILE_OPEN".
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if smb_share:
            params["smb_share"] = smb_share
        if smb_action:
            params["smb_action"] = smb_action
        records = run_query(MODULES["smb"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_ssh(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    ssh_failed_only: bool = False,
    ssh_auth_result: Optional[str] = None,
) -> str:
    """Search Zeek SSH logs from Malcolm/OpenSearch.

    Args:
        ssh_failed_only: If True, return only failed authentication attempts.
        ssh_auth_result: Auth result string to filter by, e.g. "failure", "success".
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if ssh_failed_only:
            params["ssh_failed_only"] = True
        if ssh_auth_result is not None:
            params["ssh_auth_result"] = ssh_auth_result
        records = run_query(MODULES["ssh"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_notice(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    notice_note: Optional[str] = None,
) -> str:
    """Search Zeek Notice logs from Malcolm/OpenSearch.

    Notices are high-signal events generated by Zeek policy scripts (e.g. port scans,
    SSH brute-force detected, etc.).

    Args:
        notice_note: Notice type to filter by, e.g. "Scan::Port_Scan".
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if notice_note:
            params["notice_note"] = notice_note
        records = run_query(MODULES["notice"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_weird(
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    weird_name: Optional[str] = None,
) -> str:
    """Search Zeek Weird logs from Malcolm/OpenSearch.

    Weird events represent protocol anomalies or unexpected behavior that Zeek
    couldn't classify normally.

    Args:
        weird_name: Weird event name to filter by, e.g. "bad_HTTP_reply".
    """
    try:
        params = _base_params(time_range, sensor, limit, public_only, src_ip, direction, no_filters)
        if weird_name:
            params["weird_name"] = weird_name
        records = run_query(MODULES["weird"], params)
        records = _apply_dest_ip_filter(records, dest_ip)
        return _ok({"count": len(records), "records": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Pivot tools
# ---------------------------------------------------------------------------

@mcp.tool()
def pivot_ip(
    ip: str,
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 500,
    public_only: bool = False,
    no_filters: bool = False,
) -> str:
    """Run all 10 Zeek protocol queries in parallel for a single IP address.

    Returns per-protocol record counts plus full records for every protocol where
    the IP appeared (as either source or destination).  Also runs lookup_org to
    identify cloud/CDN/scanner ownership.

    This is the primary pivot tool for IP-centric investigations.
    """
    try:
        base = _base_params(time_range, sensor, limit, public_only, ip, None, no_filters)

        org = lookup_org(ip)

        def _run(log_type: str) -> tuple[str, list]:
            try:
                params = dict(base)
                records = run_query(MODULES[log_type], params)
                # Also include records where IP is destination
                dest_hits = []
                if ip:
                    dest_params = _base_params(time_range, sensor, limit, public_only, None, None, no_filters)
                    dest_records = run_query(MODULES[log_type], dest_params)
                    dest_hits = [r for r in dest_records if r.get("dest_ip") == ip]
                # Merge, deduplicate by identity
                seen_keys: set = set()
                merged = []
                for r in records + dest_hits:
                    k = MODULES[log_type].dedup_key(r)
                    if k not in seen_keys:
                        seen_keys.add(k)
                        merged.append(r)
                return log_type, merged
            except Exception as exc:
                return log_type, []

        results: dict = {}
        with ThreadPoolExecutor(max_workers=10) as pool:
            futures = {pool.submit(_run, lt): lt for lt in MODULES}
            for future in as_completed(futures):
                log_type, records = future.result()
                results[log_type] = {
                    "count": len(records),
                    "records": _serialise_records(records),
                }

        summary = {lt: r["count"] for lt, r in results.items()}
        return _ok({
            "ip": ip,
            "org": org,
            "summary": summary,
            "protocols": results,
        })
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def pivot_alerts(
    ip: str,
    time_range: str = "now-24h",
    severity: int = 3,
    limit: int = 200,
    no_filters: bool = False,
) -> str:
    """Check whether an IP has triggered any Suricata IDS alerts.

    A fast way to answer "is this IP in my alert data?" before running a full pivot.

    Args:
        ip: IP address to check.
        severity: Maximum Suricata severity level to include (1=high, 2=medium, 3=low).
    """
    try:
        params: dict = {
            "time_range": time_range,
            "severity": severity,
            "limit": limit,
            "no_filters": no_filters,
        }
        alerts = run_kibana_query(KibanaModule(), params)
        alerts = [a for a in alerts if a.get("src_ip") == ip or a.get("dest_ip") == ip]
        return _ok({"ip": ip, "count": len(alerts), "alerts": _serialise_alerts(alerts)})
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Alert tool
# ---------------------------------------------------------------------------

@mcp.tool()
def search_alerts(
    time_range: str = "now-24h",
    severity: int = 3,
    src_ip: Optional[str] = None,
    signature: Optional[str] = None,
    min_bytes: Optional[int] = None,
    protocol: Optional[str] = None,
    limit: int = 200,
    no_filters: bool = False,
    public_only: bool = False,
) -> str:
    """Search Suricata IDS alerts via Kibana/ELK.

    Args:
        severity: Maximum severity level to include (1=critical, 2=high, 3=medium/low).
        src_ip: Filter by source IP address (post-filter).
        signature: Suricata rule signature substring to match, e.g. "ET SCAN".
        min_bytes: Minimum bytes transferred to server.
        protocol: Application protocol to filter by, e.g. "http", "tls".
    """
    try:
        params: dict = {
            "time_range": time_range,
            "severity": severity,
            "no_filters": no_filters,
            "public_only": public_only,
            "limit": limit,
        }
        if signature:
            params["signature"] = signature
        if min_bytes is not None:
            params["min_bytes"] = min_bytes
        if protocol:
            params["protocol"] = protocol

        alerts = run_kibana_query(KibanaModule(), params)

        if src_ip:
            alerts = [a for a in alerts if a.get("src_ip") == src_ip]

        return _ok({"count": len(alerts), "alerts": _serialise_alerts(alerts)})
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Enrichment / org lookup
# ---------------------------------------------------------------------------

@mcp.tool()
def enrich_ip(ip: str) -> str:
    """Run the full threat intelligence enrichment pipeline for an IP address.

    Calls in order: GreyNoise → AbuseIPDB → Shodan → VirusTotal (AbuseIPDB/Shodan/VT
    run concurrently).  If GreyNoise classifies the IP as benign, the remaining
    services are skipped.

    Also appends the org lookup result (cloud/CDN/scanner) and reference URLs
    for each service.

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
            "greynoise":  greynoise.URL.format(ip=ip),
            "abuseipdb":  abuseipdb.URL.format(ip=ip),
            "shodan":     shodan.URL.format(ip=ip),
            "virustotal": virustotal.URL.format(ip=ip),
        }
        return _ok(result)
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def lookup_ip_org(ip: str) -> str:
    """Look up the organisation, cloud provider, CDN, or scanner that owns an IP.

    Uses bundled CIDR tables (Cloudflare, Fastly, Shodan, Censys, etc.) plus a
    disk-cached copy of AWS/GCP/Azure IP ranges.  Returns None for unknown IPs.

    Returns: {name, icon, category} or null.
    """
    try:
        org = lookup_org(ip)
        return _ok({"ip": ip, "org": org})
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Utility tools
# ---------------------------------------------------------------------------

@mcp.tool()
def list_sensors(time_range: str = "now-7d") -> str:
    """List all Malcolm/Zeek sensors that have sent data in the given time window.

    Returns sensor hostnames and their record counts, sorted by volume.
    Sensor values can be passed to other tools' 'sensor' parameter to scope queries.
    """
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                        {"exists": {"field": "event.dataset"}},
                    ]
                }
            },
            "aggs": {
                "sensors": {
                    "terms": {
                        "field": "host.name",
                        "size": 500,
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        buckets = raw.get("aggregations", {}).get("sensors", {}).get("buckets", [])
        sensors = [{"name": b["key"], "record_count": b["doc_count"]} for b in buckets]
        return _ok({"time_range": time_range, "sensors": sensors})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def get_notice_summary(
    time_range: str = "now-24h",
    limit: int = 50,
) -> str:
    """Aggregate Zeek Notice types by frequency over the given time window.

    Useful for a quick overview of what Zeek policy alerts are firing without
    fetching full records.

    Returns a ranked list of (notice_note, count) pairs.
    """
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                        {"terms": {"event.dataset": MODULES["notice"].DATASETS}},
                    ]
                }
            },
            "aggs": {
                "notice_types": {
                    "terms": {
                        "field": "zeek.notice.note",
                        "size": limit,
                        "order": {"_count": "desc"},
                    }
                }
            },
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        buckets = (
            raw.get("aggregations", {})
            .get("notice_types", {})
            .get("buckets", [])
        )
        notices = [{"note": b["key"], "count": b["doc_count"]} for b in buckets]
        return _ok({"time_range": time_range, "notices": notices})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def raw_opensearch_search(
    query_body: str,
    index_path: str = f"{INDEX}/_search",
) -> str:
    """Send a raw Elasticsearch DSL query body directly to OpenSearch.

    Use this escape hatch for advanced aggregations, span queries, or any field
    access not covered by the other tools.

    Args:
        query_body: JSON string containing the full ES query body (e.g. size, query, aggs).
        index_path: Index path portion of the URL, default "arkime_sessions3-*/_search".

    Example:
        query_body = '{"size": 1, "query": {"match_all": {}}}'
    """
    try:
        try:
            body = json.loads(query_body)
        except json.JSONDecodeError as exc:
            return _err(f"Invalid JSON in query_body: {exc}")

        params = {"path": index_path, "method": "POST"}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        return _ok(raw)
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
