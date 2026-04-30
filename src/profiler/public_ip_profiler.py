"""Public IP profiler — network-perspective profiles for external hosts.

Runs 8 parallel aggregation queries against OpenSearch to build a
PublicIPProfile: sensor presence, reverse DNS, services exposed,
TLS/cert info, HTTP server headers, and inbound attack signals.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from src.querier.zeek_modules.base import INDEX, query_opensearch
from src.utils.ip_org import lookup_org

_PARAMS = {"path": f"{INDEX}/_search", "method": "POST"}


# ---------------------------------------------------------------------------
# PublicIPProfile dataclass
# ---------------------------------------------------------------------------


@dataclass
class PublicIPProfile:
    """Network-perspective profile for a public IP address."""

    ip: str
    time_range: str

    # Sensor presence
    sensors: list[dict] = field(default_factory=list)
    total_records: int = 0

    # Identity
    org: dict | None = None
    reverse_dns: list[dict] = field(default_factory=list)

    # Services exposed (our traffic TO this IP)
    services: list[dict] = field(default_factory=list)
    internal_client_count: int = 0
    bytes_to: int = 0
    bytes_from: int = 0

    # TLS (server-side)
    ja4s_fingerprints: list[dict] = field(default_factory=list)
    tls_versions: list[dict] = field(default_factory=list)
    ssl_subjects: list[str] = field(default_factory=list)
    ssl_issuers: list[str] = field(default_factory=list)

    # HTTP (server-side)
    http_server_headers: list[str] = field(default_factory=list)
    http_top_uris: list[dict] = field(default_factory=list)

    # Inbound activity FROM this IP (scanner/attacker signals)
    inbound_ports_targeted: list[dict] = field(default_factory=list)
    internal_targets_count: int = 0
    ssh_inbound: bool = False
    ssh_server_versions: list[str] = field(default_factory=list)
    rdp_inbound: bool = False
    rdp_usernames: list[str] = field(default_factory=list)

    # Classification
    role: str = "unknown"
    confidence: float = 0.0

    # Timestamps
    first_seen: str = ""
    last_seen: str = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _buckets(aggs: dict, key: str) -> list[dict]:
    """Extract buckets from an aggregation."""
    return aggs.get(key, {}).get("buckets", [])


def _ip_should(ip: str) -> list[dict]:
    """Match IP as either source or destination."""
    return [{"term": {"source.ip": ip}}, {"term": {"destination.ip": ip}}]


# ---------------------------------------------------------------------------
# Query builders (8 queries)
# ---------------------------------------------------------------------------


def _sensor_presence_query(ip: str, time_range: str) -> dict:
    """Which sensors have seen this IP, and how many records each."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"bool": {"should": _ip_should(ip)}},
                ]
            }
        },
        "aggs": {
            "sensors": {"terms": {"field": "host.name", "size": 50}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


def _reverse_dns_query(ip: str, time_range: str) -> dict:
    """Domains that resolved to this IP (from DNS answer logs)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "dns"}},
                    {"term": {"zeek.dns.answers": ip}},
                ]
            }
        },
        "aggs": {"domains": {"terms": {"field": "zeek.dns.query", "size": 20}}},
    }


def _conn_to_query(ip: str, time_range: str) -> dict:
    """Conn records where this IP is the destination (our traffic TO it)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "conn"}},
                    {"term": {"destination.ip": ip}},
                ]
            }
        },
        "aggs": {
            "dest_ports": {
                "terms": {"field": "destination.port", "size": 20},
                "aggs": {"app_proto": {"terms": {"field": "network.application", "size": 1}}},
            },
            "unique_clients": {"cardinality": {"field": "source.ip"}},
            "bytes_to": {"sum": {"field": "destination.bytes"}},
            "bytes_from": {"sum": {"field": "source.bytes"}},
            "time_range": {"stats": {"field": "@timestamp"}},
        },
    }


def _conn_from_query(ip: str, time_range: str) -> dict:
    """Conn records where this IP is the source (inbound from it)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "conn"}},
                    {"term": {"source.ip": ip}},
                ]
            }
        },
        "aggs": {
            "inbound_ports": {
                "terms": {"field": "destination.port", "size": 20},
            },
            "unique_targets": {"cardinality": {"field": "destination.ip"}},
        },
    }


def _ssl_to_query(ip: str, time_range: str) -> dict:
    """SSL/TLS records where this IP is the server (destination)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "ssl"}},
                    {"term": {"destination.ip": ip}},
                ]
            }
        },
        "aggs": {
            "ja4s": {"terms": {"field": "tls.ja4s", "size": 10}},
            "tls_versions": {"terms": {"field": "network.protocol_version", "size": 5}},
            "subjects": {"terms": {"field": "zeek.ssl.subject", "size": 10}},
            "issuers": {"terms": {"field": "zeek.ssl.issuer", "size": 10}},
        },
    }


def _http_to_query(ip: str, time_range: str) -> dict:
    """HTTP records where this IP is the server (destination)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "http"}},
                    {"term": {"destination.ip": ip}},
                ]
            }
        },
        "aggs": {
            "server_headers": {"terms": {"field": "zeek.http.server_header_names", "size": 10}},
            "top_uris": {"terms": {"field": "zeek.http.uri", "size": 10}},
        },
    }


def _ssh_from_query(ip: str, time_range: str) -> dict:
    """SSH records where this IP is the source (inbound SSH from it)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "ssh"}},
                    {"term": {"source.ip": ip}},
                ]
            }
        },
        "aggs": {
            "server_versions": {"terms": {"field": "zeek.ssh.server", "size": 5}},
        },
    }


def _rdp_from_query(ip: str, time_range: str) -> dict:
    """RDP records where this IP is the source (inbound RDP from it)."""
    return {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}},
                    {"term": {"event.dataset": "rdp"}},
                    {"term": {"source.ip": ip}},
                ]
            }
        },
        "aggs": {
            "cookies": {"terms": {"field": "zeek.rdp.cookie", "size": 10}},
        },
    }


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------


def _parse_sensor_presence(aggs: dict) -> dict:
    sensors = [{"sensor": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "sensors")]
    total = sum(s["count"] for s in sensors)
    ts = aggs.get("time_range", {})
    return {
        "sensors": sensors,
        "total_records": total,
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


def _parse_reverse_dns(aggs: dict) -> dict:
    return {
        "reverse_dns": [
            {"domain": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "domains")
        ]
    }


def _parse_conn_to(aggs: dict) -> dict:
    services = []
    for b in _buckets(aggs, "dest_ports"):
        proto_buckets = b.get("app_proto", {}).get("buckets", [])
        app_proto = proto_buckets[0]["key"] if proto_buckets else ""
        services.append(
            {
                "port": int(b["key"]),
                "app_proto": app_proto,
                "count": b["doc_count"],
            }
        )
    ts = aggs.get("time_range", {})
    return {
        "services": services,
        "internal_client_count": int(aggs.get("unique_clients", {}).get("value", 0)),
        "bytes_to": int(aggs.get("bytes_to", {}).get("value", 0)),
        "bytes_from": int(aggs.get("bytes_from", {}).get("value", 0)),
        "first_seen": ts.get("min_as_string", ""),
        "last_seen": ts.get("max_as_string", ""),
    }


def _parse_conn_from(aggs: dict) -> dict:
    return {
        "inbound_ports_targeted": [
            {"port": int(b["key"]), "count": b["doc_count"]}
            for b in _buckets(aggs, "inbound_ports")
        ],
        "internal_targets_count": int(aggs.get("unique_targets", {}).get("value", 0)),
    }


def _parse_ssl_to(aggs: dict) -> dict:
    return {
        "ja4s_fingerprints": [
            {"hash": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "ja4s")
        ],
        "tls_versions": [
            {"version": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "tls_versions")
        ],
        "ssl_subjects": [b["key"] for b in _buckets(aggs, "subjects")],
        "ssl_issuers": [b["key"] for b in _buckets(aggs, "issuers")],
    }


def _parse_http_to(aggs: dict) -> dict:
    return {
        "http_server_headers": [b["key"] for b in _buckets(aggs, "server_headers")],
        "http_top_uris": [
            {"uri": b["key"], "count": b["doc_count"]} for b in _buckets(aggs, "top_uris")
        ],
    }


def _parse_ssh_from(aggs: dict) -> dict:
    count = sum(b["doc_count"] for b in _buckets(aggs, "server_versions"))
    # If no server_versions buckets, check if the query itself had hits
    total = aggs.get("server_versions", {}).get("sum_other_doc_count", 0) + count
    return {
        "ssh_inbound": total > 0 or count > 0,
        "ssh_server_versions": [b["key"] for b in _buckets(aggs, "server_versions")],
    }


def _parse_rdp_from(aggs: dict) -> dict:
    cookies = _buckets(aggs, "cookies")
    total = sum(b["doc_count"] for b in cookies)
    return {
        "rdp_inbound": total > 0,
        "rdp_usernames": [b["key"] for b in cookies],
    }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


def profile_public_ip(
    ip: str,
    *,
    time_range: str = "now-7d",
) -> PublicIPProfile:
    """Profile a public IP using 8 parallel Zeek log aggregations.

    Args:
        ip: Public IP address to profile.
        time_range: Elasticsearch date-math range (default: now-7d).

    Returns:
        PublicIPProfile with all fields populated.
    """
    org = lookup_org(ip)

    queries: dict[str, dict] = {
        "sensor": _sensor_presence_query(ip, time_range),
        "rdns": _reverse_dns_query(ip, time_range),
        "conn_to": _conn_to_query(ip, time_range),
        "conn_from": _conn_from_query(ip, time_range),
        "ssl_to": _ssl_to_query(ip, time_range),
        "http_to": _http_to_query(ip, time_range),
        "ssh_from": _ssh_from_query(ip, time_range),
        "rdp_from": _rdp_from_query(ip, time_range),
    }

    results: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=8) as ex:
        futures = {
            ex.submit(query_opensearch, body, _PARAMS): name for name, body in queries.items()
        }
        for f in as_completed(futures):
            name = futures[f]
            raw = f.result()
            results[name] = raw.get("aggregations", {}) if raw else {}

    sensor = _parse_sensor_presence(results.get("sensor", {}))
    rdns = _parse_reverse_dns(results.get("rdns", {}))
    conn_to = _parse_conn_to(results.get("conn_to", {}))
    conn_from = _parse_conn_from(results.get("conn_from", {}))
    ssl_to = _parse_ssl_to(results.get("ssl_to", {}))
    http_to = _parse_http_to(results.get("http_to", {}))
    ssh_from = _parse_ssh_from(results.get("ssh_from", {}))
    rdp_from = _parse_rdp_from(results.get("rdp_from", {}))

    first_seen = min(
        (t for t in [sensor["first_seen"], conn_to["first_seen"]] if t),
        default="",
    )
    last_seen = max(
        (t for t in [sensor["last_seen"], conn_to["last_seen"]] if t),
        default="",
    )

    profile = PublicIPProfile(
        ip=ip,
        time_range=time_range,
        org=org,
        sensors=sensor["sensors"],
        total_records=sensor["total_records"],
        reverse_dns=rdns["reverse_dns"],
        services=conn_to["services"],
        internal_client_count=conn_to["internal_client_count"],
        bytes_to=conn_to["bytes_to"],
        bytes_from=conn_to["bytes_from"],
        ja4s_fingerprints=ssl_to["ja4s_fingerprints"],
        tls_versions=ssl_to["tls_versions"],
        ssl_subjects=ssl_to["ssl_subjects"],
        ssl_issuers=ssl_to["ssl_issuers"],
        http_server_headers=http_to["http_server_headers"],
        http_top_uris=http_to["http_top_uris"],
        inbound_ports_targeted=conn_from["inbound_ports_targeted"],
        internal_targets_count=conn_from["internal_targets_count"],
        ssh_inbound=ssh_from["ssh_inbound"],
        ssh_server_versions=ssh_from["ssh_server_versions"],
        rdp_inbound=rdp_from["rdp_inbound"],
        rdp_usernames=rdp_from["rdp_usernames"],
        first_seen=first_seen,
        last_seen=last_seen,
    )

    from src.profiler.public_role_classifier import classify_public_role

    profile.role, profile.confidence = classify_public_role(profile)

    return profile
