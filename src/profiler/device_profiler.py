#!/usr/bin/env python3
"""Device profiler — private IP fingerprinting via Zeek logs.

Runs 9 parallel aggregation queries against OpenSearch to build a DeviceProfile
for a single private IP on a specific sensor.

Usage:
    uv run src/profiler/device_profiler.py --ip <private-ip> --sensor <sensor-hostname>
"""

from __future__ import annotations

import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.querier.zeek_modules.base import (
    INDEX,
    is_private,
    query_opensearch,
)

_PARAMS = {"path": f"{INDEX}/_search", "method": "POST"}


# ---------------------------------------------------------------------------
# DeviceProfile dataclass
# ---------------------------------------------------------------------------


@dataclass
class DeviceProfile:
    """Device profile built from 9 parallel Zeek log aggregations."""

    ip: str
    sensor: str
    time_range: str

    # Identity (from inbound SMB UNC paths)
    hostname: str | None = None
    ad_domain: str | None = None

    # Classification
    role: str = "unknown"
    confidence: float = 0.0
    os_family: str | None = None
    software: list[str] = field(default_factory=list)

    # Outbound conn (device as client)
    dest_port_distribution: dict[int, int] = field(default_factory=dict)
    protocol_mix: dict[str, int] = field(default_factory=dict)
    unique_dest_count: int = 0
    bytes_sent: int = 0
    ja4t_fingerprints: list[dict] = field(default_factory=list)

    # Inbound conn (device as server)
    inbound_services: list[dict] = field(default_factory=list)
    inbound_client_count: int = 0
    bytes_received: int = 0

    # DNS
    dns_top_domains: list[dict] = field(default_factory=list)
    dns_qtypes: list[dict] = field(default_factory=list)
    dns_resolvers: list[str] = field(default_factory=list)

    # SSL/TLS
    ja4_fingerprints: list[dict] = field(default_factory=list)
    ssl_sni_values: list[str] = field(default_factory=list)
    tls_versions: list[dict] = field(default_factory=list)

    # HTTP
    user_agents: list[str] = field(default_factory=list)
    user_agent_os: list[str] = field(default_factory=list)
    http_top_hosts: list[dict] = field(default_factory=list)
    ja4h_fingerprints: list[dict] = field(default_factory=list)
    http_proxy_count: int = 0

    # SMB
    smb_shares_accessed: list[str] = field(default_factory=list)
    smb_shares_hosted: list[str] = field(default_factory=list)

    # RDP
    rdp_inbound: bool = False
    rdp_usernames: list[str] = field(default_factory=list)
    admin_targets: list[str] = field(default_factory=list)

    # SSH
    ssh_inbound: bool = False
    hassh_fingerprints: list[dict] = field(default_factory=list)
    hassh_server_fingerprints: list[dict] = field(default_factory=list)
    ssh_client_versions: list[str] = field(default_factory=list)
    ssh_server_versions: list[str] = field(default_factory=list)
    ssh_admin_targets: list[str] = field(default_factory=list)

    # DHCP
    mac: str | None = None
    dhcp_hostname: str | None = None

    # Users (from Kerberos/NTLM)
    users: list[str] = field(default_factory=list)

    # Timestamps
    first_seen: str = ""
    last_seen: str = ""


# ---------------------------------------------------------------------------
# Aggregation queries
# ---------------------------------------------------------------------------


def _conn_outbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Build conn-outbound aggregation body (device as source)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("source.ip", ip, "conn", time_range, sensor)}},
        "aggs": {
            "dest_ports": {"terms": {"field": "destination.port", "size": 10}},
            "app_protos": {"terms": {"field": "network.application", "size": 10}},
            "unique_dests": {"cardinality": {"field": "destination.ip"}},
            "total_bytes": {"sum": {"field": "source.bytes"}},
            "ja4t_fingerprints": {"terms": {"field": "zeek.conn.ja4t", "size": 5}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


def _conn_inbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Build conn-inbound aggregation body (device as destination)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("destination.ip", ip, "conn", time_range, sensor)}},
        "aggs": {
            "inbound_ports": {
                "terms": {"field": "destination.port", "size": 20},
                "aggs": {"app_proto": {"terms": {"field": "network.application", "size": 1}}},
            },
            "unique_clients": {"cardinality": {"field": "source.ip"}},
            "total_bytes": {"sum": {"field": "destination.bytes"}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


# ---------------------------------------------------------------------------
# Query builders — outbound queries #2-#5
# ---------------------------------------------------------------------------


def _base_must(ip_field: str, ip: str, dataset: str, time_range: str, sensor: str) -> list:
    """Shared must clauses for all aggregation queries."""
    clauses = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
        {"term": {"event.dataset": dataset}},
        {"term": {ip_field: ip}},
    ]
    if sensor and sensor.lower() != "all":
        clauses.append({"term": {"host.name": sensor}})
    return clauses


def _dns_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #2: DNS domains queried (device as source)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("source.ip", ip, "dns", time_range, sensor)}},
        "aggs": {
            "top_domains": {"terms": {"field": "zeek.dns.query", "size": 20}},
            "qtypes": {"terms": {"field": "zeek.dns.qtype_name", "size": 10}},
            "resolvers": {"terms": {"field": "destination.ip", "size": 5}},
        },
    }


def _ssl_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #3: SSL/TLS JA4 fingerprints (device as source)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("source.ip", ip, "ssl", time_range, sensor)}},
        "aggs": {
            "ja4_hashes": {"terms": {"field": "tls.ja4", "size": 20}},
            "sni_values": {"terms": {"field": "zeek.ssl.server_name", "size": 20}},
            "tls_versions": {"terms": {"field": "network.protocol_version", "size": 5}},
        },
    }


def _http_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #4: HTTP user agents, hosts, JA4H (device as source)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("source.ip", ip, "http", time_range, sensor)}},
        "aggs": {
            "user_agents": {"terms": {"field": "user_agent.original", "size": 10}},
            "ua_os_names": {"terms": {"field": "user_agent.os.name", "size": 5}},
            "top_hosts": {"terms": {"field": "zeek.http.host", "size": 15}},
            "ja4h_fingerprints": {"terms": {"field": "zeek.http.ja4h", "size": 10}},
            "proxy_connects": {"filter": {"term": {"zeek.http.method": "CONNECT"}}},
        },
    }


def _smb_outbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #5: SMB shares accessed (device as source, smb_mapping only)."""
    return {
        "size": 0,
        "query": {"bool": {"must": _base_must("source.ip", ip, "smb_mapping", time_range, sensor)}},
        "aggs": {
            "remote_paths": {"terms": {"field": "zeek.smb_mapping.path", "size": 20}},
        },
    }


# ---------------------------------------------------------------------------
# Query builders — inbound queries #7-#9
# ---------------------------------------------------------------------------


def _smb_inbound_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #7: SMB shares hosted + hostname extraction (device as dest)."""
    return {
        "size": 0,
        "query": {
            "bool": {"must": _base_must("destination.ip", ip, "smb_mapping", time_range, sensor)}
        },
        "aggs": {
            "unc_paths": {"terms": {"field": "zeek.smb_mapping.path", "size": 20}},
        },
    }


def _rdp_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #8: RDP inbound + outbound (bidirectional)."""
    must: list = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
        {"term": {"event.dataset": "rdp"}},
        {"bool": {"should": [{"term": {"source.ip": ip}}, {"term": {"destination.ip": ip}}]}},
    ]
    if sensor and sensor.lower() != "all":
        must.append({"term": {"host.name": sensor}})
    return {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "inbound": {
                "filter": {"term": {"destination.ip": ip}},
                "aggs": {
                    "cookies": {"terms": {"field": "zeek.rdp.cookie", "size": 10}},
                },
            },
            "outbound": {
                "filter": {"term": {"source.ip": ip}},
                "aggs": {
                    "targets": {"terms": {"field": "destination.ip", "size": 10}},
                },
            },
        },
    }


def _ssh_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #9: SSH inbound + outbound + HASSH (bidirectional)."""
    must: list = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
        {"term": {"event.dataset": "ssh"}},
        {"bool": {"should": [{"term": {"source.ip": ip}}, {"term": {"destination.ip": ip}}]}},
    ]
    if sensor and sensor.lower() != "all":
        must.append({"term": {"host.name": sensor}})
    return {
        "size": 0,
        "query": {"bool": {"must": must}},
        "aggs": {
            "inbound": {
                "filter": {"term": {"destination.ip": ip}},
                "aggs": {
                    "hassh_server": {"terms": {"field": "ssh.hasshServer", "size": 5}},
                    "server_versions": {"terms": {"field": "zeek.ssh.server", "size": 5}},
                },
            },
            "outbound": {
                "filter": {"term": {"source.ip": ip}},
                "aggs": {
                    "targets": {"terms": {"field": "destination.ip", "size": 10}},
                    "hassh_client": {"terms": {"field": "ssh.hassh", "size": 5}},
                    "client_versions": {"terms": {"field": "zeek.ssh.client", "size": 5}},
                },
            },
        },
    }


# ---------------------------------------------------------------------------
# Query builders — DHCP (#10), Kerberos/NTLM (#11)
# ---------------------------------------------------------------------------


def _dhcp_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #10: DHCP lease lookup by assigned IP → MAC + hostname."""
    return {
        "size": 0,
        "query": {
            "bool": {"must": _base_must("zeek.dhcp.assigned_ip", ip, "dhcp", time_range, sensor)}
        },
        "aggs": {
            "mac": {"terms": {"field": "zeek.dhcp.mac", "size": 5}},
            "hostname": {"terms": {"field": "zeek.dhcp.host_name", "size": 5}},
        },
    }


def _kerberos_ntlm_query(ip: str, time_range: str, sensor: str) -> dict:
    """Query #11: Kerberos client + NTLM username from this IP."""
    must_base: list = [
        {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
        {"term": {"source.ip": ip}},
        {"terms": {"event.dataset": ["kerberos", "ntlm"]}},
    ]
    if sensor and sensor.lower() != "all":
        must_base.append({"term": {"host.name": sensor}})
    return {
        "size": 0,
        "query": {"bool": {"must": must_base}},
        "aggs": {
            "krb_clients": {"terms": {"field": "zeek.kerberos.client", "size": 10}},
            "ntlm_users": {"terms": {"field": "zeek.ntlm.username", "size": 10}},
        },
    }


# ---------------------------------------------------------------------------
# Hostname extraction from UNC paths
# ---------------------------------------------------------------------------


def extract_hostname_from_unc(paths: list[str]) -> tuple[str | None, str | None]:
    """Extract hostname and AD domain from inbound SMB UNC paths.

    Parses paths like ``\\\\SERVER.domain.example.com\\IPC$`` and returns
    (hostname, ad_domain).  Returns the most common hostname if multiple
    are found.
    """
    hostnames: dict[str, int] = {}
    domains: dict[str, int] = {}
    for path in paths:
        stripped = path.lstrip("\\")
        server_part = stripped.split("\\")[0] if "\\" in stripped else stripped
        if not server_part:
            continue
        if "." in server_part:
            host = server_part.split(".")[0].upper()
            domain = server_part[len(host) + 1 :]
            hostnames[host] = hostnames.get(host, 0) + 1
            if domain:
                domains[domain] = domains.get(domain, 0) + 1
        else:
            host = server_part.upper()
            hostnames[host] = hostnames.get(host, 0) + 1

    hostname = max(hostnames, key=hostnames.get) if hostnames else None
    ad_domain = max(domains, key=domains.get) if domains else None
    return hostname, ad_domain


def _extract_share_names(paths: list[str]) -> list[str]:
    """Extract share names from UNC paths (e.g. ``\\\\SRV\\IPC$`` → ``IPC$``)."""
    shares: set[str] = set()
    for path in paths:
        parts = path.lstrip("\\").split("\\")
        if len(parts) >= 2 and parts[1]:
            shares.add(parts[1])
    return sorted(shares)


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def _parse_outbound(aggs: dict) -> dict:
    """Extract outbound fields from aggregation response."""
    dest_ports = {
        int(b["key"]): b["doc_count"] for b in aggs.get("dest_ports", {}).get("buckets", [])
    }
    app_protos = {b["key"]: b["doc_count"] for b in aggs.get("app_protos", {}).get("buckets", [])}
    ja4t = [
        {"hash": b["key"], "count": b["doc_count"]}
        for b in aggs.get("ja4t_fingerprints", {}).get("buckets", [])
    ]
    ts = aggs.get("time_range", {})
    return {
        "dest_port_distribution": dest_ports,
        "protocol_mix": app_protos,
        "unique_dest_count": int(aggs.get("unique_dests", {}).get("value", 0)),
        "bytes_sent": int(aggs.get("total_bytes", {}).get("value", 0)),
        "ja4t_fingerprints": ja4t,
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


def _parse_inbound(aggs: dict) -> dict:
    """Extract inbound fields from aggregation response."""
    services = []
    for b in aggs.get("inbound_ports", {}).get("buckets", []):
        proto_buckets = b.get("app_proto", {}).get("buckets", [])
        app_proto = proto_buckets[0]["key"] if proto_buckets else ""
        services.append({"port": int(b["key"]), "app_proto": app_proto, "count": b["doc_count"]})
    ts = aggs.get("time_range", {})
    return {
        "inbound_services": services,
        "inbound_client_count": int(aggs.get("unique_clients", {}).get("value", 0)),
        "bytes_received": int(aggs.get("total_bytes", {}).get("value", 0)),
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


def _buckets(aggs: dict, key: str) -> list[dict]:
    """Shorthand to extract buckets from an aggregation."""
    return aggs.get(key, {}).get("buckets", [])


def _parse_dns(aggs: dict) -> dict:
    """Extract DNS fields from aggregation response."""
    return {
        "dns_top_domains": [
            {"domain": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "top_domains")
        ],
        "dns_qtypes": [
            {"qtype": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "qtypes")
        ],
        "dns_resolvers": [b["key"] for b in _buckets(aggs, "resolvers")],
    }


def _parse_ssl(aggs: dict) -> dict:
    """Extract SSL/TLS fields from aggregation response."""
    return {
        "ja4_fingerprints": [
            {"hash": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "ja4_hashes")
        ],
        "ssl_sni_values": [b["key"] for b in _buckets(aggs, "sni_values")],
        "tls_versions": [
            {"version": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "tls_versions")
        ],
    }


def _parse_http(aggs: dict) -> dict:
    """Extract HTTP fields from aggregation response."""
    return {
        "user_agents": [b["key"] for b in _buckets(aggs, "user_agents")],
        "user_agent_os": [b["key"] for b in _buckets(aggs, "ua_os_names")],
        "http_top_hosts": [
            {"host": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "top_hosts")
        ],
        "ja4h_fingerprints": [
            {"hash": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "ja4h_fingerprints")
        ],
        "http_proxy_count": aggs.get("proxy_connects", {}).get("doc_count", 0),
    }


def _parse_smb_outbound(aggs: dict) -> dict:
    """Extract outbound SMB share paths."""
    paths = [b["key"] for b in _buckets(aggs, "remote_paths")]
    return {"smb_shares_accessed": _extract_share_names(paths)}


def _parse_smb_inbound(aggs: dict) -> dict:
    """Extract inbound SMB paths → hostname, AD domain, shares hosted."""
    paths = [b["key"] for b in _buckets(aggs, "unc_paths")]
    hostname, ad_domain = extract_hostname_from_unc(paths)
    return {
        "hostname": hostname,
        "ad_domain": ad_domain,
        "smb_shares_hosted": _extract_share_names(paths),
    }


def _parse_rdp(aggs: dict) -> dict:
    """Extract RDP inbound/outbound fields."""
    inb = aggs.get("inbound", {})
    outb = aggs.get("outbound", {})
    return {
        "rdp_inbound": inb.get("doc_count", 0) > 0,
        "rdp_usernames": [b["key"] for b in _buckets(inb, "cookies")],
        "admin_targets": [b["key"] for b in _buckets(outb, "targets")],
    }


def _parse_ssh(aggs: dict) -> dict:
    """Extract SSH inbound/outbound + HASSH fields."""
    inb = aggs.get("inbound", {})
    outb = aggs.get("outbound", {})
    return {
        "ssh_inbound": inb.get("doc_count", 0) > 0,
        "hassh_fingerprints": [
            {"hash": b["key"], "count": b["doc_count"]} for b in _buckets(outb, "hassh_client")
        ],
        "hassh_server_fingerprints": [
            {"hash": b["key"], "count": b["doc_count"]} for b in _buckets(inb, "hassh_server")
        ],
        "ssh_client_versions": [b["key"] for b in _buckets(outb, "client_versions")],
        "ssh_server_versions": [b["key"] for b in _buckets(inb, "server_versions")],
        "ssh_admin_targets": [b["key"] for b in _buckets(outb, "targets")],
    }


def _parse_dhcp(aggs: dict) -> dict:
    """Extract MAC and DHCP hostname."""
    macs = _buckets(aggs, "mac")
    hostnames = _buckets(aggs, "hostname")
    return {
        "mac": macs[0]["key"] if macs else None,
        "dhcp_hostname": hostnames[0]["key"] if hostnames else None,
    }


def _parse_kerberos_ntlm(aggs: dict) -> dict:
    """Extract unique usernames from Kerberos client + NTLM username."""
    users: set[str] = set()
    for b in _buckets(aggs, "krb_clients"):
        users.add(b["key"])
    for b in _buckets(aggs, "ntlm_users"):
        users.add(b["key"])
    return {"users": sorted(users)}


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def profile_device(
    ip: str,
    *,
    time_range: str = "now-7d",
    sensor: str = "all",
) -> DeviceProfile:
    """Profile a private IP using 9 parallel Zeek log aggregations.

    Args:
        ip: Private IP address to profile.
        time_range: Elasticsearch date-math range (default: now-7d).
        sensor: Sensor hostname (required — private IPs overlap across sensors).

    Returns:
        DeviceProfile with all fields populated.

    Raises:
        ValueError: If the IP is not a private/RFC-1918 address.
    """
    if not is_private(ip):
        raise ValueError(f"{ip} is not a private IP — use enrich_ip() for public IPs")

    queries: dict[str, dict] = {
        "conn_out": _conn_outbound_query(ip, time_range, sensor),
        "conn_in": _conn_inbound_query(ip, time_range, sensor),
        "dns": _dns_query(ip, time_range, sensor),
        "ssl": _ssl_query(ip, time_range, sensor),
        "http": _http_query(ip, time_range, sensor),
        "smb_out": _smb_outbound_query(ip, time_range, sensor),
        "smb_in": _smb_inbound_query(ip, time_range, sensor),
        "rdp": _rdp_query(ip, time_range, sensor),
        "ssh": _ssh_query(ip, time_range, sensor),
        "dhcp": _dhcp_query(ip, time_range, sensor),
        "krb_ntlm": _kerberos_ntlm_query(ip, time_range, sensor),
    }

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=len(queries)) as ex:
        futures = {
            ex.submit(query_opensearch, body, _PARAMS): name for name, body in queries.items()
        }
        for f in as_completed(futures):
            name = futures[f]
            raw = f.result()
            results[name] = raw.get("aggregations", {}) if raw else {}

    out = _parse_outbound(results.get("conn_out", {}))
    inb = _parse_inbound(results.get("conn_in", {}))
    dns = _parse_dns(results.get("dns", {}))
    ssl = _parse_ssl(results.get("ssl", {}))
    http = _parse_http(results.get("http", {}))
    smb_out = _parse_smb_outbound(results.get("smb_out", {}))
    smb_in = _parse_smb_inbound(results.get("smb_in", {}))
    rdp = _parse_rdp(results.get("rdp", {}))
    ssh = _parse_ssh(results.get("ssh", {}))
    dhcp = _parse_dhcp(results.get("dhcp", {}))
    krb_ntlm = _parse_kerberos_ntlm(results.get("krb_ntlm", {}))

    # Merge timestamps — take the earliest first_seen and latest last_seen.
    first_seen = min((t for t in [out["first_seen"], inb["first_seen"]] if t), default="")
    last_seen = max((t for t in [out["last_seen"], inb["last_seen"]] if t), default="")

    profile = DeviceProfile(
        ip=ip,
        sensor=sensor,
        time_range=time_range,
        hostname=dhcp["dhcp_hostname"] or smb_in["hostname"],
        ad_domain=smb_in["ad_domain"],
        dest_port_distribution=out["dest_port_distribution"],
        protocol_mix=out["protocol_mix"],
        unique_dest_count=out["unique_dest_count"],
        bytes_sent=out["bytes_sent"],
        ja4t_fingerprints=out["ja4t_fingerprints"],
        inbound_services=inb["inbound_services"],
        inbound_client_count=inb["inbound_client_count"],
        bytes_received=inb["bytes_received"],
        dns_top_domains=dns["dns_top_domains"],
        dns_qtypes=dns["dns_qtypes"],
        dns_resolvers=dns["dns_resolvers"],
        ja4_fingerprints=ssl["ja4_fingerprints"],
        ssl_sni_values=ssl["ssl_sni_values"],
        tls_versions=ssl["tls_versions"],
        user_agents=http["user_agents"],
        user_agent_os=http["user_agent_os"],
        http_top_hosts=http["http_top_hosts"],
        ja4h_fingerprints=http["ja4h_fingerprints"],
        http_proxy_count=http["http_proxy_count"],
        smb_shares_accessed=smb_out["smb_shares_accessed"],
        smb_shares_hosted=smb_in["smb_shares_hosted"],
        rdp_inbound=rdp["rdp_inbound"],
        rdp_usernames=rdp["rdp_usernames"],
        admin_targets=rdp["admin_targets"],
        ssh_inbound=ssh["ssh_inbound"],
        hassh_fingerprints=ssh["hassh_fingerprints"],
        hassh_server_fingerprints=ssh["hassh_server_fingerprints"],
        ssh_client_versions=ssh["ssh_client_versions"],
        ssh_server_versions=ssh["ssh_server_versions"],
        ssh_admin_targets=ssh["ssh_admin_targets"],
        mac=dhcp["mac"],
        dhcp_hostname=dhcp["dhcp_hostname"],
        users=krb_ntlm["users"],
        first_seen=first_seen,
        last_seen=last_seen,
    )

    # Classification layer — runs on the populated profile
    from src.profiler.role_classifier import classify_role, detect_os
    from src.profiler.software_signatures import match_software

    profile.role, profile.confidence = classify_role(profile)
    profile.os_family = detect_os(profile)
    profile.software = match_software(profile)

    return profile


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _display_profile(profile: DeviceProfile) -> None:
    """Render a DeviceProfile as Rich tables."""
    from rich import box
    from rich.console import Console
    from rich.table import Table

    from src.utils.format import fmt_bytes

    console = Console()

    # Header
    name = profile.hostname or profile.ip
    if profile.ad_domain:
        name += f".{profile.ad_domain}"
    console.print(
        f"\n[bold]Device Profile:[/bold] {name}"
        f"  [dim]({profile.ip})  sensor={profile.sensor}  range={profile.time_range}[/dim]"
    )
    role_str = profile.role.replace("_", " ").title()
    conf_pct = int(profile.confidence * 100)
    os_str = profile.os_family.title() if profile.os_family else "Unknown"
    console.print(
        f"[bold]Role:[/bold] {role_str} ({conf_pct}% confidence)  [bold]OS:[/bold] {os_str}"
    )
    if profile.software:
        console.print(f"[bold]Software:[/bold] {', '.join(profile.software)}")
    if profile.mac:
        console.print(f"[bold]MAC:[/bold] {profile.mac}")
    if profile.users:
        console.print(f"[bold]Users:[/bold] {', '.join(profile.users)}")
    if profile.first_seen:
        console.print(
            f"[dim]First seen: {profile.first_seen[:19]}  Last seen: {profile.last_seen[:19]}[/dim]"
        )

    # Inbound services
    if profile.inbound_services:
        t = Table(title="Inbound Services", box=box.SIMPLE_HEAVY, expand=False)
        t.add_column("Port", justify="right")
        t.add_column("Protocol")
        t.add_column("Count", justify="right")
        for svc in profile.inbound_services:
            t.add_row(str(svc["port"]), svc["app_proto"] or "—", str(svc["count"]))
        console.print(t)
    console.print(
        f"[dim]Inbound clients: {profile.inbound_client_count}  "
        f"Bytes recv: {fmt_bytes(profile.bytes_received)}  "
        f"Bytes sent: {fmt_bytes(profile.bytes_sent)}  "
        f"Unique dests: {profile.unique_dest_count}[/dim]"
    )

    # DNS
    if profile.dns_top_domains:
        t = Table(title="Top DNS Domains", box=box.SIMPLE_HEAVY, expand=False)
        t.add_column("Domain")
        t.add_column("Count", justify="right")
        for d in profile.dns_top_domains[:10]:
            t.add_row(d["domain"], str(d["count"]))
        console.print(t)

    # TLS / JA4
    if profile.ja4_fingerprints:
        t = Table(title="JA4 TLS Fingerprints", box=box.SIMPLE_HEAVY, expand=False)
        t.add_column("Hash")
        t.add_column("Count", justify="right")
        for fp in profile.ja4_fingerprints:
            t.add_row(fp["hash"], str(fp["count"]))
        console.print(t)

    if profile.ssl_sni_values:
        console.print(f"[dim]SNI: {', '.join(profile.ssl_sni_values[:10])}[/dim]")

    # HTTP
    if profile.user_agents:
        console.print(f"[bold]User Agents:[/bold] {', '.join(profile.user_agents[:5])}")
    if profile.user_agent_os:
        console.print(f"[dim]OS (from UA): {', '.join(profile.user_agent_os)}[/dim]")

    # SMB
    if profile.smb_shares_hosted:
        console.print(f"[bold]SMB Shares Hosted:[/bold] {', '.join(profile.smb_shares_hosted)}")
    if profile.smb_shares_accessed:
        console.print(f"[bold]SMB Shares Accessed:[/bold] {', '.join(profile.smb_shares_accessed)}")

    # RDP / SSH / Admin
    parts: list[str] = []
    if profile.rdp_inbound:
        users = ", ".join(profile.rdp_usernames) if profile.rdp_usernames else "yes"
        parts.append(f"RDP inbound ({users})")
    if profile.ssh_inbound:
        parts.append("SSH inbound")
    if profile.admin_targets:
        parts.append(f"RDP admin → {', '.join(profile.admin_targets[:5])}")
    if profile.ssh_admin_targets:
        parts.append(f"SSH admin → {', '.join(profile.ssh_admin_targets[:5])}")
    if parts:
        console.print(f"[bold]Remote Access:[/bold] {' · '.join(parts)}")

    if profile.ssh_server_versions:
        console.print(f"[dim]SSH server: {', '.join(profile.ssh_server_versions)}[/dim]")
    if profile.ssh_client_versions:
        console.print(f"[dim]SSH client: {', '.join(profile.ssh_client_versions)}[/dim]")

    # Fingerprints summary
    fp_parts: list[str] = []
    if profile.ja4t_fingerprints:
        fp_parts.append(f"JA4T: {len(profile.ja4t_fingerprints)}")
    if profile.ja4h_fingerprints:
        fp_parts.append(f"JA4H: {len(profile.ja4h_fingerprints)}")
    if profile.hassh_fingerprints:
        fp_parts.append(f"HASSH: {len(profile.hassh_fingerprints)}")
    if profile.hassh_server_fingerprints:
        fp_parts.append(f"HASSHServer: {len(profile.hassh_server_fingerprints)}")
    if fp_parts:
        console.print(f"[dim]Fingerprints: {' · '.join(fp_parts)}[/dim]")


def main() -> None:
    """CLI entry point for device profiler."""
    load_dotenv()

    from src.utils.dns import setup_dns

    setup_dns()

    parser = argparse.ArgumentParser(
        description="PISCES Device Profiler — private IP fingerprinting via Zeek logs"
    )
    parser.add_argument("--ip", required=True, help="Private IP to profile")
    parser.add_argument(
        "--sensor",
        required=True,
        help="Sensor hostname (required — private IPs overlap across sensors)",
    )
    parser.add_argument(
        "--time-range", default="now-7d", help="ES date-math range (default: now-7d)"
    )
    parser.add_argument("--json", action="store_true", dest="json_output", help="Output as JSON")
    args = parser.parse_args()

    profile = profile_device(args.ip, time_range=args.time_range, sensor=args.sensor)

    if args.json_output:
        import json
        from dataclasses import asdict

        print(json.dumps(asdict(profile), indent=2, default=str))
    else:
        _display_profile(profile)


if __name__ == "__main__":
    main()
