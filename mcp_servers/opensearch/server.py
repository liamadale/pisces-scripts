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
import math
import os
import sys
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

from src.enricher.threat_intel import enrich_ip
from src.querier.histogram import query_histogram
from src.querier.fp_manager import (
    append_clauses_to_file,
    delete_ip_from_filter,
    ensure_subcategory,
    filter_file_path,
    load_categories,
    load_filter_file,
)
from src.querier.runner import FILTERS_DIR, load_with_remap
from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import (
    INDEX,
    build_base_query,
    is_private,
    query_opensearch,
    run_query,
)
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


def _search_result(records: list, limit: int) -> dict:
    """Build a standard search response dict with a truncation hint."""
    return {
        "count": len(records),
        "truncated": len(records) >= limit,
        "records": _serialise_records(records),
    }


def _ok(data) -> str:
    return json.dumps({"status": "ok", "data": data}, default=str)


def _err(msg: str) -> str:
    return json.dumps({"status": "error", "message": msg})


def _base_params(
    time_range: str,
    sensor: str | list[str],
    limit: int,
    public_only: bool,
    src_ip: str | list[str] | None,
    direction: Optional[str],
    no_filters: bool,
    dest_ip: str | list[str] | None = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
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
    if dest_ip:
        params["dest_ip"] = dest_ip
    if direction:
        params["direction"] = direction
    if time_from:
        params["time_from"] = time_from
    if time_to:
        params["time_to"] = time_to
    return params


# ---------------------------------------------------------------------------
# 10 Zeek protocol tools
# ---------------------------------------------------------------------------


@mcp.tool()
def search_conn(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    dest_port: Optional[int] = None,
    src_port: Optional[int] = None,
    proto: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek conn (connection) logs from Malcolm/OpenSearch.

    Returns deduplicated connection records sorted by frequency.
    Common fields: src_ip, dest_ip, dest_port, proto, bytes, duration, sensor.

    Args:
        dest_port: Destination port to filter by, e.g. 443.
        src_port: Source port to filter by.
        proto: Transport protocol to filter by, e.g. "tcp", "udp", "icmp".
        time_from: Absolute start timestamp (ISO 8601), e.g. "2026-04-19T00:00:00Z".
        time_to: Absolute end timestamp (ISO 8601). Overrides time_range when both are set.
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if dest_port is not None:
            params["dest_port"] = dest_port
        if src_port is not None:
            params["src_port"] = src_port
        if proto:
            params["proto"] = proto
        records = run_query(MODULES["conn"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_dns(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    dns_query: Optional[str] = None,
    dns_rcode: Optional[str] = None,
    dns_qtype: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek DNS logs from Malcolm/OpenSearch.

    Args:
        dns_query: Domain name to filter by (substring match).
        dns_rcode: Response code to filter by, e.g. "NXDOMAIN".
        dns_qtype: Query type to filter by, e.g. "A", "MX", "TXT".
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if dns_query:
            params["dns_query"] = dns_query
        if dns_rcode:
            params["rcode"] = dns_rcode
        if dns_qtype:
            params["qtype"] = dns_qtype
        records = run_query(MODULES["dns"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_http(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    http_method: Optional[str] = None,
    http_host: Optional[str] = None,
    http_uri: Optional[str] = None,
    status_code: Optional[int] = None,
    dest_port: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek HTTP logs from Malcolm/OpenSearch.

    Args:
        http_method: HTTP method filter, e.g. "POST", "GET".
        http_host: Virtual host header to filter by.
        http_uri: URI path substring to filter by.
        status_code: HTTP response status code to filter by.
        dest_port: Destination port to filter by (default 80/8080, but not enforced).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if http_method:
            params["http_method"] = http_method
        if http_host:
            params["http_host"] = http_host
        if http_uri:
            params["http_uri"] = http_uri
        if status_code is not None:
            params["status_code"] = status_code
        if dest_port is not None:
            params["dest_port"] = dest_port
        records = run_query(MODULES["http"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_ssl(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    ssl_sni: Optional[str] = None,
    ssl_invalid_only: bool = False,
    dest_port: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek SSL/TLS logs from Malcolm/OpenSearch.

    Args:
        ssl_sni: Server Name Indication hostname to filter by.
        ssl_invalid_only: If True, return only connections with invalid/self-signed certs.
        dest_port: Destination port to filter by (commonly 443, 8443).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if ssl_sni:
            params["ssl_sni"] = ssl_sni
        if ssl_invalid_only:
            params["ssl_invalid_only"] = True
        if dest_port is not None:
            params["dest_port"] = dest_port
        records = run_query(MODULES["ssl"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_smtp(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    smtp_mail_from: Optional[str] = None,
    smtp_rcpt_to: Optional[str] = None,
    smtp_subject: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek SMTP logs from Malcolm/OpenSearch.

    Args:
        smtp_mail_from: Sender address to filter by.
        smtp_rcpt_to: Recipient address to filter by.
        smtp_subject: Subject line substring to filter by.
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if smtp_mail_from:
            params["smtp_mail_from"] = smtp_mail_from
        if smtp_rcpt_to:
            params["smtp_rcpt_to"] = smtp_rcpt_to
        if smtp_subject:
            params["smtp_subject"] = smtp_subject
        records = run_query(MODULES["smtp"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_rdp(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    rdp_result: Optional[str] = None,
    rdp_cookie: Optional[str] = None,
    dest_port: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek RDP logs from Malcolm/OpenSearch.

    Args:
        rdp_result: RDP result string to filter by, e.g. "encrypted".
        rdp_cookie: RDP cookie/username string to filter by.
        dest_port: Destination port to filter by (commonly 3389).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if rdp_result:
            params["rdp_result"] = rdp_result
        if rdp_cookie:
            params["rdp_cookie"] = rdp_cookie
        if dest_port is not None:
            params["dest_port"] = dest_port
        records = run_query(MODULES["rdp"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_smb(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    smb_share: Optional[str] = None,
    smb_action: Optional[str] = None,
    dest_port: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek SMB logs from Malcolm/OpenSearch.

    Args:
        smb_share: SMB share name to filter by.
        smb_action: SMB action verb to filter by, e.g. "SMB::FILE_OPEN".
        dest_port: Destination port to filter by (commonly 445).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if smb_share:
            params["smb_share"] = smb_share
        if smb_action:
            params["smb_action"] = smb_action
        if dest_port is not None:
            params["dest_port"] = dest_port
        records = run_query(MODULES["smb"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_ssh(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    ssh_failed_only: bool = False,
    ssh_auth_result: Optional[str] = None,
    dest_port: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek SSH logs from Malcolm/OpenSearch.

    Args:
        ssh_failed_only: If True, return only failed authentication attempts.
        ssh_auth_result: Auth result string to filter by, e.g. "failure", "success".
        dest_port: Destination port to filter by (commonly 22).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if ssh_failed_only:
            params["ssh_failed_only"] = True
        if ssh_auth_result is not None:
            params["ssh_auth_result"] = ssh_auth_result
        if dest_port is not None:
            params["dest_port"] = dest_port
        records = run_query(MODULES["ssh"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_notice(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    notice_note: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek Notice logs from Malcolm/OpenSearch.

    Notices are high-signal events generated by Zeek policy scripts (e.g. port scans,
    SSH brute-force detected, etc.).

    Args:
        notice_note: Notice type to filter by, e.g. "Scan::Port_Scan". Use a trailing
            wildcard to match a namespace, e.g. "Scan::*" or "SSH::*".
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if notice_note:
            params["notice_note"] = notice_note
        records = run_query(MODULES["notice"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_weird(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    weird_name: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek Weird logs from Malcolm/OpenSearch.

    Weird events represent protocol anomalies or unexpected behavior that Zeek
    couldn't classify normally.

    Args:
        weird_name: Weird event name to filter by, e.g. "bad_HTTP_reply". Supports
            wildcards, e.g. "bad_*".
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if weird_name:
            params["weird_name"] = weird_name
        records = run_query(MODULES["weird"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_suricata_alert(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    direction: Optional[str] = None,
    no_filters: bool = False,
    rule_name: Optional[str] = None,
    rule_category: Optional[str] = None,
    severity: Optional[int] = None,
    sid: Optional[int] = None,
    exclude_stream: bool = False,
    tag: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Suricata IDS alert records from Malcolm/OpenSearch.

    Suricata alerts complement Zeek notices with signature-based detection.
    Use exclude_stream=True or severity=1 to skip protocol anomaly noise
    (~99.6% of records are severity 3 STREAM/QUIC anomalies).

    Args:
        rule_name: Filter by rule name (wildcard match).
        rule_category: Filter by rule category, e.g. "Potentially Bad Traffic".
        severity: Suricata severity level (1=high, 2=medium, 3=low).
        sid: Suricata rule ID (SID) to filter by.
        exclude_stream: Exclude noisy SURICATA STREAM/QUIC protocol anomaly rules.
        tag: Filter by tag, e.g. "CISA_KEV", "Exploit", "RAT".
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            direction,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if rule_name:
            params["rule_name"] = rule_name
        if rule_category:
            params["rule_category"] = rule_category
        if severity is not None:
            params["severity"] = severity
        if sid is not None:
            params["sid"] = sid
        if exclude_stream:
            params["exclude_stream"] = True
        if tag:
            params["tag"] = tag
        records = run_query(MODULES["suricata_alert"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Phase 4 Tier 2 protocol tools — RADIUS, SIP, Tunnel
# ---------------------------------------------------------------------------


@mcp.tool()
def search_radius(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    username: Optional[str] = None,
    mac: Optional[str] = None,
    failed_only: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek RADIUS authentication logs — VPN/802.1X auth records.

    Args:
        username: Filter by username (substring match).
        mac: Filter by MAC address (exact match).
        failed_only: Show only failed authentication attempts.
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if username:
            params["username"] = username
        if mac:
            params["mac"] = mac
        if failed_only:
            params["failed_only"] = failed_only
        records = run_query(MODULES["radius"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_sip(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    method: Optional[str] = None,
    status_code: Optional[str] = None,
    user_agent: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek SIP/VoIP session logs.

    Args:
        method: Filter by SIP method (INVITE, REGISTER, OPTIONS, etc.).
        status_code: Filter by SIP status code (exact match).
        user_agent: Filter by User-Agent (substring match).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if method:
            params["method"] = method
        if status_code:
            params["status_code"] = status_code
        if user_agent:
            params["user_agent"] = user_agent
        records = run_query(MODULES["sip"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_tunnel(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    tunnel_type: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek tunnel logs — protocol encapsulation / covert channel detection.

    Args:
        tunnel_type: Filter by tunnel type (Tunnel::IP, Tunnel::GRE, etc.).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if tunnel_type:
            params["tunnel_type"] = tunnel_type
        records = run_query(MODULES["tunnel"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_ntp(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    mode: Optional[int] = None,
    version: Optional[int] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek NTP logs — time synchronisation and amplification detection.

    Args:
        mode: Filter by NTP mode (3=client, 4=server, 6=control, 7=private).
        version: Filter by NTP version (exact match, integer).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if mode is not None:
            params["mode"] = mode
        if version is not None:
            params["version"] = version
        records = run_query(MODULES["ntp"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_modbus(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    function: Optional[str] = None,
    exceptions_only: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek Modbus/TCP logs — OT/SCADA protocol for PLCs and RTUs.

    Args:
        function: Filter by Modbus function (e.g. "Read Coils", "Write Single Register").
        exceptions_only: Show only records with exception codes.
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if function:
            params["function"] = function
        if exceptions_only:
            params["exceptions_only"] = True
        records = run_query(MODULES["modbus"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def search_dnp3(
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    limit: int = 500,
    public_only: bool = False,
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    function: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Search Zeek DNP3 logs — SCADA protocol for utilities (electric, water, gas).

    Args:
        function: Filter by DNP3 function request (substring match).
        time_from: Absolute start timestamp (ISO 8601). Overrides time_range when both are set.
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        params = _base_params(
            time_range,
            sensor,
            limit,
            public_only,
            src_ip,
            None,
            no_filters,
            dest_ip,
            time_from,
            time_to,
        )
        if function:
            params["function"] = function
        records = run_query(MODULES["dnp3"], params)
        return _ok(_search_result(records, limit))
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Pivot tool (§2.1)
# ---------------------------------------------------------------------------


@mcp.tool()
def pivot(
    ip: str,
    mode: str = "records",
    dest_ip: Optional[str] = None,
    sensor: str = "all",
    time_range: str = "now-24h",
    limit: int = 500,
    public_only: bool = False,
    no_filters: bool = False,
) -> str:
    """IP-centric investigation tool with three operating modes.

    Choose ``mode`` based on the question you are trying to answer:

    * **records** — Cross-protocol raw records for *ip* (as src or dest).
      Returns per-protocol counts plus full deduplicated records.  Also runs
      ``lookup_org`` to surface cloud/CDN/scanner ownership.  Use when you
      want to see what an IP was actually doing.

    * **profile** — Aggregated device card for *ip*.  For private IPs: role,
      OS, software, inbound services, hostnames, fingerprints.  For public
      IPs: sensor presence, reverse DNS, exposed services, TLS/cert info,
      inbound attack signals.  Use when you want to understand what a device
      is, not just what it did.

    * **incident** — Full incident bundle for a src/dest pair.  Requires
      ``dest_ip``.  Runs device profiling, auth history, attack chain, Mantis
      ticket search, and threat-intel enrichment in parallel.  Use for
      alert triage or incident response.

    Args:
        ip: IP address to pivot on (actor / attacker for ``mode="incident"``).
        mode: One of "records", "profile", or "incident".
        dest_ip: Destination IP — required when ``mode="incident"``.
        sensor: Sensor hostname.  Required for private-IP profiling; "all" for
                ``mode="records"``.
        time_range: ES date-math range, e.g. "now-24h" or "now-7d".
        limit: Max records per protocol (``mode="records"`` only).
        public_only: Exclude RFC-1918 addresses (``mode="records"`` only).
        no_filters: Bypass FP filter files (``mode="records"`` only).
    """
    try:
        if mode == "records":
            base = _base_params(time_range, sensor, limit, public_only, ip, None, no_filters)

            org = lookup_org(ip)

            def _run(log_type: str) -> tuple[str, list]:
                try:
                    params = dict(base)
                    records = run_query(MODULES[log_type], params)
                    dest_hits: list = []
                    if ip:
                        dest_params = _base_params(
                            time_range, sensor, limit, public_only, None, None, no_filters
                        )
                        dest_records = run_query(MODULES[log_type], dest_params)
                        dest_hits = [r for r in dest_records if r.get("dest_ip") == ip]
                    seen_keys: set = set()
                    merged = []
                    for r in records + dest_hits:
                        k = MODULES[log_type].dedup_key(r)
                        if k not in seen_keys:
                            seen_keys.add(k)
                            merged.append(r)
                    return log_type, merged
                except Exception:
                    return log_type, []

            results: dict = {}
            with ThreadPoolExecutor(max_workers=10) as pool:
                futures = {pool.submit(_run, lt): lt for lt in MODULES}
                for future in as_completed(futures):
                    lt, recs = future.result()
                    results[lt] = {
                        "count": len(recs),
                        "records": _serialise_records(recs),
                    }

            summary = {lt: r["count"] for lt, r in results.items()}
            return _ok({"ip": ip, "org": org, "summary": summary, "protocols": results})

        elif mode == "profile":
            from dataclasses import asdict

            if is_private(ip):
                from src.profiler.device_profiler import profile_device as _profile_device

                profile = _profile_device(ip, time_range=time_range, sensor=sensor)
            else:
                from src.profiler.public_ip_profiler import profile_public_ip

                profile = profile_public_ip(ip, time_range=time_range)
            return _ok(asdict(profile))

        elif mode == "incident":
            if not dest_ip:
                return _err("dest_ip is required when mode='incident'")
            from dataclasses import asdict

            from src.correlator.incident_context import investigate as _investigate

            ctx = _investigate(ip, dest_ip, sensor, time_range)
            data = asdict(ctx)
            for key in ("src_profile", "dest_profile"):
                p = data.get(key)
                if p is not None:
                    data[key] = {
                        "ip": p["ip"],
                        "hostname": p.get("hostname"),
                        "role": p["role"],
                        "confidence": p["confidence"],
                        "os_family": p.get("os_family"),
                        "software": p.get("software", []),
                        "users": p.get("users", []),
                        "inbound_services": p.get("inbound_services", []),
                    }
            return _ok(data)

        else:
            return _err(f"Unknown mode '{mode}'. Must be 'records', 'profile', or 'incident'.")
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
        buckets = raw.get("aggregations", {}).get("notice_types", {}).get("buckets", [])
        notices = [{"note": b["key"], "count": b["doc_count"]} for b in buckets]
        return _ok({"time_range": time_range, "notices": notices})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def raw_opensearch_search(
    query_body: str,
    index_path: str = f"{INDEX}/_search",
    method: str = "POST",
) -> str:
    """Send a raw Elasticsearch DSL query body directly to OpenSearch.

    Use this escape hatch for advanced aggregations, span queries, non-default
    index queries, or any field access not covered by the other tools.

    Args:
        query_body: JSON string containing the full ES query body. Pass '{}' for GET requests.
        index_path: Index path portion of the URL, default "arkime_sessions3-*/_search".
                    Use "_cat/indices?format=json&s=docs.count:desc" to discover available indices.
        method: HTTP method the proxy will use against ES — "POST" (default) or "GET".
                Use "GET" for _cat/* and other read-only ES APIs that don't accept a body.
    """
    try:
        try:
            body = json.loads(query_body)
        except json.JSONDecodeError as exc:
            return _err(f"Invalid JSON in query_body: {exc}")

        params = {"path": index_path, "method": method}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        return _ok(raw)
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Aggregation / analysis tools
# ---------------------------------------------------------------------------


@mcp.tool()
def aggregate(
    field: str,
    log_type: Optional[str] = None,
    notice_type: Optional[str] = None,
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 25,
) -> str:
    """Rank any ES field by frequency across Zeek logs.

    Generic aggregation primitive.  Common uses:

    * Top source IPs for a notice:
      ``field="source.ip", log_type="notice", notice_type="Scan::Port_Scan"``
    * Top destination IPs overall: ``field="destination.ip"``
    * Top destination ports: ``field="destination.port", log_type="conn"``
    * Top user agents: ``field="zeek.http.user_agent", log_type="http"``

    Args:
        field: ES field name to aggregate on, e.g. "source.ip", "destination.port".
        log_type: Scope to a single Zeek module's datasets, e.g. "conn", "notice",
                  "http".  Omit to aggregate across all datasets.
        notice_type: Filter by exact Zeek notice type (only meaningful with
                     ``log_type="notice"``), e.g. "Scan::Port_Scan".
        time_range: ES date-math range, e.g. "now-24h".
        sensor: Sensor hostname or "all".
        limit: Maximum number of buckets to return.
    """
    try:
        must: list = [{"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}]
        if log_type and log_type in MODULES:
            must.append({"terms": {"event.dataset": MODULES[log_type].DATASETS}})
        if notice_type:
            must.append({"term": {"zeek.notice.note": notice_type}})
        if sensor != "all":
            must.append({"terms": {"host.name": [s.strip() for s in sensor.split(",")]}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "buckets": {
                    "terms": {
                        "field": field,
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
        buckets = raw.get("aggregations", {}).get("buckets", {}).get("buckets", [])
        results = [{"value": b["key"], "count": b["doc_count"]} for b in buckets]
        return _ok(
            {
                "field": field,
                "log_type": log_type,
                "notice_type": notice_type,
                "time_range": time_range,
                "results": results,
            }
        )
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def get_attack_chain(
    src_ip: str,
    time_range: str = "now-24h",
    sensor: str = "all",
    no_filters: bool = False,
) -> str:
    """Retrieve all ATTACK::* Zeek notices from a single source IP in chronological order.

    Reconstructs a kill-chain narrative without requiring multiple search_notice calls.
    Returns notices sorted by timestamp ascending so the sequence of events is clear.

    Args:
        src_ip: Source IP address to investigate.
        no_filters: If True, bypass FP filter files (show suppressed events too).
    """
    try:
        must: list = [
            {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
            {"terms": {"event.dataset": MODULES["notice"].DATASETS}},
            {"term": {"source.ip": src_ip}},
            {"prefix": {"zeek.notice.note": "ATTACK::"}},
        ]
        if sensor != "all":
            must.append({"terms": {"host.name": [s.strip() for s in sensor.split(",")]}})
        body = {
            "size": 500,
            "query": {"bool": {"must": must}},
            "sort": [{"@timestamp": {"order": "asc"}}],
            "_source": MODULES["notice"].SOURCE_FIELDS,
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        hits = raw.get("hits", {}).get("hits", [])
        records = [MODULES["notice"].parse_hit(h["_source"]) for h in hits]
        return _ok({"ip": src_ip, "count": len(records), "chain": _serialise_records(records)})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def enrich_top_talkers(
    notice_type: str,
    time_range: str = "now-24h",
    sensor: str = "all",
    limit: int = 10,
) -> str:
    """Aggregate top source IPs for a notice type and enrich them all in one call.

    Combines aggregate_by_source_ip + bulk enrich_ip. Private/RFC-1918 IPs are
    skipped (no enrichment data available for them).

    Args:
        notice_type: Exact notice type to filter by, e.g. "SSH::Password_Guessing".
        limit: Maximum number of top IPs to enrich.
    """
    try:
        must: list = [
            {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
            {"terms": {"event.dataset": MODULES["notice"].DATASETS}},
            {"term": {"zeek.notice.note": notice_type}},
        ]
        if sensor != "all":
            must.append({"terms": {"host.name": [s.strip() for s in sensor.split(",")]}})
        body = {
            "size": 0,
            "query": {"bool": {"must": must}},
            "aggs": {
                "top_sources": {
                    "terms": {
                        "field": "source.ip",
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
        buckets = raw.get("aggregations", {}).get("top_sources", {}).get("buckets", [])
        public_ips = [(b["key"], b["doc_count"]) for b in buckets if not is_private(b["key"])]

        def _enrich_one(item: tuple) -> dict:
            ip, count = item
            enrichment = enrich_ip(ip, offer_fp=False)
            return {"ip": ip, "count": count, "enrichment": enrichment}

        results: list = []
        if public_ips:
            with ThreadPoolExecutor(max_workers=min(len(public_ips), 5)) as pool:
                futures = {pool.submit(_enrich_one, item): item for item in public_ips}
                for future in as_completed(futures):
                    results.append(future.result())
            results.sort(key=lambda x: x["count"], reverse=True)

        return _ok({"notice_type": notice_type, "time_range": time_range, "results": results})
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def bulk_enrich_ips(ips: list[str]) -> str:
    """Enrich a list of IP addresses through the full threat-intelligence pipeline.

    Runs GreyNoise → AbuseIPDB → Shodan → VirusTotal concurrently for each public IP.
    Private/RFC-1918 IPs are skipped — no enrichment data is available for them.
    Results are returned in the same order as the input list.

    Args:
        ips: List of IP addresses to enrich.
    """
    try:
        ip_order = {ip: i for i, ip in enumerate(ips)}
        public = [ip for ip in ips if not is_private(ip)]
        private_count = len(ips) - len(public)

        def _enrich_one(ip: str) -> dict:
            return {"ip": ip, "enrichment": enrich_ip(ip, offer_fp=False)}

        results: list = []
        if public:
            with ThreadPoolExecutor(max_workers=min(len(public), 5)) as pool:
                futures = {pool.submit(_enrich_one, ip): ip for ip in public}
                for future in as_completed(futures):
                    results.append(future.result())
            results.sort(key=lambda x: ip_order.get(x["ip"], len(ips)))

        return _ok(
            {
                "total_requested": len(ips),
                "enriched_count": len(results),
                "skipped_private": private_count,
                "results": results,
            }
        )
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def count(
    log_type: str,
    time_range: str = "now-24h",
    sensor: str | list[str] = "all",
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    no_filters: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Count matching events without fetching records — cheaper than search for pure counts.

    Hits the ``_count`` endpoint so no documents are shipped.  Use this when you
    only need a number, e.g. to check whether an IP is active before pivoting, or
    to compare volume across time windows.

    Args:
        log_type: Zeek log type, e.g. "conn", "notice", "dns". Use "all" for all datasets.
        time_range: ES date-math range, ignored when time_from/time_to are set.
        sensor: Sensor hostname or "all".
        src_ip: Source IP or list of source IPs to filter by.
        dest_ip: Destination IP or list of destination IPs to filter by.
        no_filters: Skip FP filters.
        time_from: Absolute start timestamp (ISO 8601).
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        if no_filters:
            must_not: list = []
        else:
            must_not, _fc, _errs = load_with_remap(FILTERS_DIR)

        sensors: list | None = None
        if isinstance(sensor, list):
            sensors = [s.strip() for s in sensor]
        elif str(sensor).lower() != "all":
            sensors = [s.strip() for s in str(sensor).split(",")]

        datasets = MODULES[log_type].DATASETS if log_type in MODULES and log_type != "all" else []

        body, _params = build_base_query(
            must_not=must_not,
            extra_must=[],
            source_fields=[],
            limit=0,
            time_range=time_range,
            sensors=sensors,
            datasets=datasets,
            src_ip_filter=src_ip,
            dest_ip_filter=dest_ip,
            time_from=time_from,
            time_to=time_to,
            sort=False,
        )
        count_body = {"query": body["query"]}
        params = {"path": f"{INDEX}/_count", "method": "POST"}
        raw = query_opensearch(count_body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        return _ok(
            {
                "log_type": log_type,
                "time_range": time_range,
                "count": raw.get("count", 0),
            }
        )
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def compare_to_baseline(
    notice_type: str,
    current_count: int,
    baseline_days: int = 30,
) -> str:
    """Compare a current notice count against a historical daily baseline.

    Computes daily mean and stddev from a date histogram over the last
    baseline_days days, then calculates a z-score for current_count.

    Assessment thresholds: |z| < 1 → normal, 1-2 → elevated, 2-3 → high,
    > 3 → significantly elevated. When stddev is zero (all days identical),
    returns a ratio vs mean instead of a z-score.

    Args:
        notice_type: Exact notice type to analyse, e.g. "Scan::Port_Scan".
        current_count: The count you want to compare against baseline.
        baseline_days: How many past days to use for the baseline (default 30).
    """
    try:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": f"now-{baseline_days}d",
                                    "lte": "now",
                                }
                            }
                        },
                        {"terms": {"event.dataset": MODULES["notice"].DATASETS}},
                        {"term": {"zeek.notice.note": notice_type}},
                    ]
                }
            },
            "aggs": {
                "daily": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1d"}}
            },
        }
        params = {"path": f"{INDEX}/_search", "method": "POST"}
        raw = query_opensearch(body, params)
        if raw is None:
            return _err("OpenSearch query failed — check credentials and OPENSEARCH_URL")
        buckets = raw.get("aggregations", {}).get("daily", {}).get("buckets", [])
        counts = [b["doc_count"] for b in buckets] if buckets else []

        if not counts:
            return _ok(
                {
                    "notice_type": notice_type,
                    "current_count": current_count,
                    "baseline_daily_mean": 0,
                    "baseline_daily_stddev": 0,
                    "z_score": None,
                    "assessment": "no baseline data available",
                }
            )

        mean = sum(counts) / len(counts)
        variance = sum((c - mean) ** 2 for c in counts) / len(counts)
        stddev = math.sqrt(variance)

        if stddev == 0:
            ratio = current_count / mean if mean > 0 else 0.0
            if ratio < 1.1:
                assessment = "normal"
            elif ratio < 2:
                assessment = "elevated"
            elif ratio < 3:
                assessment = "high"
            else:
                assessment = "significantly elevated"
            return _ok(
                {
                    "notice_type": notice_type,
                    "current_count": current_count,
                    "baseline_daily_mean": round(mean, 2),
                    "baseline_daily_stddev": 0,
                    "z_score": None,
                    "ratio_vs_mean": round(ratio, 2),
                    "assessment": assessment,
                }
            )

        z = (current_count - mean) / stddev
        abs_z = abs(z)
        if abs_z < 1:
            assessment = "normal"
        elif abs_z < 2:
            assessment = "elevated"
        elif abs_z < 3:
            assessment = "high"
        else:
            assessment = "significantly elevated"

        return _ok(
            {
                "notice_type": notice_type,
                "current_count": current_count,
                "baseline_daily_mean": round(mean, 2),
                "baseline_daily_stddev": round(stddev, 2),
                "z_score": round(z, 2),
                "assessment": assessment,
            }
        )
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def create_fp_filter(
    src_ip: str,
    category: str,
    subcategory: str,
    scope: str = "src_ip",
    notice_note: str = "",
    comment: str = "",
) -> str:
    """Create a false-positive filter file entry non-interactively.

    Writes a must_not clause to filters/{category}/{subcategory}.yaml and
    registers the category/subcategory in categories.yaml.

    Args:
        src_ip: Source IP address to suppress.
        category: Filter category directory, e.g. "ips" or "notices".
        subcategory: Filter subcategory (filename without .yaml), e.g. "false_positives".
        scope: "src_ip" suppresses all alerts from this IP; "src_ip_and_note"
               suppresses only the specific notice type (requires notice_note).
        notice_note: Exact notice type, e.g. "Scan::Port_Scan". Required when
                     scope="src_ip_and_note".
        comment: Optional comment to embed in the filter clause.
    """
    try:
        if scope == "src_ip_and_note" and not notice_note:
            return _err("notice_note is required when scope='src_ip_and_note'")
        if scope not in ("src_ip", "src_ip_and_note"):
            return _err(f"Invalid scope '{scope}'. Must be 'src_ip' or 'src_ip_and_note'.")

        if scope == "src_ip":
            clause: dict = {"term": {"src_ip": src_ip}}
        else:
            clause = {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"term": {"zeek.notice.note": notice_note}},
                    ]
                }
            }

        if comment:
            clause["comment"] = comment

        path = filter_file_path(category, subcategory)
        append_clauses_to_file(path, [clause], author="mcp")
        ensure_subcategory(category, subcategory)

        return _ok(
            {
                "written": True,
                "file": path,
                "scope": scope,
                "src_ip": src_ip,
                "notice_note": notice_note or None,
                "category": category,
                "subcategory": subcategory,
            }
        )
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def list_filter_categories() -> str:
    """List all valid filter category / subcategory pairs from categories.yaml.

    Returns a mapping of category → list[subcategory].  Use this before calling
    create_fp_filter so you can supply a valid category and subcategory.
    """
    try:
        data = load_categories()
        cats = data.get("categories", {})
        return _ok(cats)
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def list_fp_filters(
    category: Optional[str] = None,
    subcategory: Optional[str] = None,
) -> str:
    """Read existing false-positive filter clauses.

    When called with no arguments returns a summary of all filter files.
    When called with only category returns all files in that category.
    When called with both category and subcategory returns the full clause list
    for that file so you can inspect what is already suppressed.

    Args:
        category: Filter category directory, e.g. "ips" or "notices".
        subcategory: Filter subcategory (filename without .yaml), e.g. "false_positives".
    """
    try:
        import os

        if category and subcategory:
            path = filter_file_path(category, subcategory)
            if not os.path.exists(path):
                return _err(f"Filter file not found: filters/{category}/{subcategory}.yaml")
            data = load_filter_file(path)
            return _ok(
                {
                    "category": category,
                    "subcategory": subcategory,
                    "enabled": data.get("enabled", True),
                    "description": data.get("description", ""),
                    "clause_count": len(data.get("must_not", [])),
                    "clauses": data.get("must_not", []),
                }
            )

        results = []
        cats = load_categories().get("categories", {})

        for cat, cat_data in sorted(cats.items()):
            if category and cat != category:
                continue
            for sub in sorted(cat_data.get("subcategories", [])):
                path = filter_file_path(cat, sub)
                if os.path.exists(path):
                    fdata = load_filter_file(path)
                    results.append(
                        {
                            "category": cat,
                            "subcategory": sub,
                            "enabled": fdata.get("enabled", True),
                            "clause_count": len(fdata.get("must_not", [])),
                        }
                    )
                else:
                    results.append(
                        {"category": cat, "subcategory": sub, "enabled": None, "clause_count": 0}
                    )

        return _ok(results)
    except Exception as exc:
        return _err(str(exc))


@mcp.tool()
def delete_fp_filter(
    category: str,
    subcategory: str,
    ip: str,
) -> str:
    """Remove false-positive filter clauses that match an IP address.

    Removes every must_not clause in filters/{category}/{subcategory}.yaml
    where the given IP appears as a src_ip or dest_ip value (handles both
    single-value ``term`` and multi-value ``terms`` clauses).  For ``terms``
    clauses with multiple IPs, only the matching IP is removed; the clause is
    kept with the remaining IPs.

    Args:
        category: Filter category directory, e.g. "ips".
        subcategory: Filter subcategory (filename without .yaml), e.g. "false_positives".
        ip: IP address to remove from the filter file.
    """
    try:
        path = filter_file_path(category, subcategory)
        removed = delete_ip_from_filter(path, ip)
        data = load_filter_file(path)
        return _ok(
            {
                "deleted": removed,
                "remaining_clauses": len(data.get("must_not", [])),
                "file": path,
                "ip": ip,
            }
        )
    except (FileNotFoundError, ValueError) as exc:
        return _err(str(exc))
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Share URLs
# ---------------------------------------------------------------------------


@mcp.tool()
def build_share_urls(
    time_range: str = "now-24h",
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    src_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    sensor: str = "all",
    log_type: Optional[str] = None,
    page_type: str = "overview",
    extra_params: Optional[dict] = None,
    columns: Optional[list] = None,
) -> str:
    """Build shareable PISCES and OpenSearch Dashboards URLs for a search view.

    Generates two link types:
    1. PISCES link — URL back to the PISCES web app with absolute timestamps
    2. OpenSearch Dashboards link — opens the same KQL query in Discover

    Tries to shorten the Dashboards link via Malcolm's /api/shorten_url API;
    falls back to the full long URL if that fails.

    Args:
        time_range: Relative time range, e.g. "now-24h". Used when time_from/time_to
            are not provided.
        time_from: Absolute start timestamp (ISO 8601), e.g. "2026-04-19T00:00:00Z".
        time_to: Absolute end timestamp (ISO 8601), e.g. "2026-04-20T00:00:00Z".
        src_ip: Source IP filter.
        dest_ip: Destination IP filter.
        sensor: Sensor hostname or "all".
        log_type: Protocol/module name, e.g. "conn", "suricata_alert", "notice".
            When set, sensible default columns are chosen automatically.
        page_type: "overview", "log", or "ip_pivot".
        extra_params: Protocol-specific filters, e.g. {"rule_name": "ET CINS..."}.
        columns: Explicit list of OpenSearch field names to show as Discover columns.
            Overrides the automatic defaults. e.g. ["source.ip", "destination.ip",
            "rule.name", "tags"]. If None, uses sensible per-protocol defaults.
    """
    try:
        from src.utils.share_url import (
            ShareContext,
            build_dashboards_path,
            build_pisces_url,
            shorten_dashboards_url,
        )

        if time_from and time_to:
            resolved_from, resolved_to = time_from, time_to
        else:
            from apps.opensearch_web.app import resolve_time_range

            resolved_from, resolved_to = resolve_time_range(time_range)

        ctx = ShareContext(
            src_ip=src_ip,
            dest_ip=dest_ip,
            sensor=sensor,
            time_from=resolved_from,
            time_to=resolved_to,
            log_type=log_type,
            page_type=page_type,
            extra_params=extra_params or {},
        )

        pisces_url = build_pisces_url(ctx, script_name="/opensearch")
        discover_path = build_dashboards_path(ctx, columns=columns)

        dashboards_base = os.environ.get("OPENSEARCH_URL", "")
        short_url = None
        if dashboards_base:
            username = os.environ.get("PISCES_USERNAME", "")
            password = os.environ.get("PISCES_PASSWORD", "")
            if username and password:
                short_url = shorten_dashboards_url(
                    discover_path, dashboards_base, (username, password)
                )

        long_url = (dashboards_base + discover_path) if dashboards_base else ""

        return _ok(
            {
                "pisces": pisces_url,
                "dashboards": short_url or long_url,
                "dashboards_long": long_url,
                "kql": ctx.extra_params,
                "time_from": resolved_from,
                "time_to": resolved_to,
            }
        )
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# §4.9 Date-histogram primitive
# ---------------------------------------------------------------------------


@mcp.tool()
def histogram(
    log_type: str,
    interval: str = "1h",
    time_range: str = "now-24h",
    src_ip: str | list[str] | None = None,
    dest_ip: str | list[str] | None = None,
    sensor: str | list[str] = "all",
    no_filters: bool = False,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
) -> str:
    """Return a date histogram of event volume over time for a Zeek log type.

    Buckets are sorted chronologically. Use this to spot traffic spikes, quiet
    periods, or to establish a baseline before diving into per-record searches.

    Args:
        log_type: Zeek log type (e.g. "conn", "notice", "dns") or "all" for all datasets.
        interval: Bucket width in ES fixed_interval notation, e.g. "15m", "1h", "6h", "1d".
        time_range: ES date-math range (default: now-24h). Ignored when time_from/time_to are set.
        src_ip: Filter to a source IP or list of source IPs.
        dest_ip: Filter to a destination IP or list of destination IPs.
        sensor: Sensor hostname or list of hostnames; "all" returns all sensors.
        no_filters: Skip false-positive YAML filters (useful for debugging).
        time_from: Absolute start timestamp (ISO 8601), e.g. "2026-04-19T00:00:00Z".
        time_to: Absolute end timestamp (ISO 8601).
    """
    try:
        buckets = query_histogram(
            log_type=log_type,
            interval=interval,
            time_range=time_range,
            src_ip=src_ip,
            dest_ip=dest_ip,
            sensor=sensor,
            no_filters=no_filters,
            time_from=time_from,
            time_to=time_to,
        )
        total = sum(b["doc_count"] for b in buckets)
        return _ok(
            {
                "log_type": log_type,
                "interval": interval,
                "bucket_count": len(buckets),
                "total_events": total,
                "buckets": buckets,
            }
        )
    except Exception as exc:
        return _err(str(exc))


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")
