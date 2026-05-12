#!/usr/bin/env python3
"""OpenSearch DSL query construction: field remapping and query body building."""

import ipaddress

from src.querier.client import INDEX

# Field name translation: Kibana convention → Malcolm/Zeek field
FIELD_MAP = {
    "src_ip": "source.ip",
    "dest_ip": "destination.ip",
    "src_port": "source.port",
    "dest_port": "destination.port",
    "app_proto": "network.protocol",
    "clientID": "host.name",
}

TIME_RANGES = [
    "now-15m",
    "now-30m",
    "now-1h",
    "now-3h",
    "now-6h",
    "now-12h",
    "now-24h",
    "now-2d",
    "now-3d",
    "now-7d",
    "now-14d",
    "now-30d",
]

# Non-routable CIDRs excluded by --public-only.
_PRIVATE_CIDRS = [
    # IPv4
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",  # link-local / APIPA
    # IPv6
    "::1/128",  # loopback
    "fe80::/10",  # link-local
    "fc00::/7",  # unique-local (fd00::/8 etc.)
    "ff00::/8",  # multicast
]

# Precomputed once: a single must_not clause that matches any source IP in a
# private range.  `term` does not evaluate CIDR notation on ip-typed fields —
# range queries with explicit network/broadcast bounds are the correct DSL.
_PRIVATE_CIDR_MUST_NOT: dict = {
    "bool": {
        "should": [
            {
                "range": {
                    "source.ip": {
                        "gte": str(ipaddress.ip_network(cidr, strict=False).network_address),
                        "lte": str(ipaddress.ip_network(cidr, strict=False).broadcast_address),
                    }
                }
            }
            for cidr in _PRIVATE_CIDRS
        ]
    }
}


def is_private(ip: str) -> bool:
    """Return True if *ip* falls within any RFC-1918 / non-routable range."""
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(cidr) for cidr in _PRIVATE_CIDRS)
    except ValueError:
        return False


def _remap_clause(clause: dict) -> dict:
    """Recursively remap Kibana field names to Malcolm/Zeek field names.

    Walks a DSL clause dict and renames any key found in FIELD_MAP.
    Handles term, terms, range, match_phrase, bool (recurses into
    must/must_not/should/filter). Pure function — returns a new dict.
    """
    if not isinstance(clause, dict):
        return clause

    result = {}
    for key, value in clause.items():
        if key in (
            "term",
            "terms",
            "range",
            "match_phrase",
            "match",
            "wildcard",
            "prefix",
            "regexp",
        ):
            remapped_inner = {}
            for field, field_val in value.items():
                new_field = FIELD_MAP.get(field, field)
                remapped_inner[new_field] = field_val
            result[key] = remapped_inner
        elif key == "bool":
            new_bool = {}
            for bool_key, bool_val in value.items():
                if bool_key in ("must", "must_not", "should", "filter"):
                    if isinstance(bool_val, list):
                        new_bool[bool_key] = [_remap_clause(c) for c in bool_val]
                    else:
                        new_bool[bool_key] = _remap_clause(bool_val)
                else:
                    new_bool[bool_key] = bool_val
            result[key] = new_bool
        else:
            result[key] = value

    return result


def build_base_query(
    must_not: list,
    extra_must: list,
    source_fields: list,
    limit: int,
    time_range: str,
    sensors: list | None,
    datasets: list,
    public_only: bool = False,
    src_ip_filter: str | list[str] | None = None,
    dest_ip_filter: str | list[str] | None = None,
    any_ip_filter: str | None = None,
    direction: str | None = None,
    time_from: str | None = None,
    time_to: str | None = None,
    sort: bool = True,
    src_port_filter: int | list[int] | None = None,
    dest_port_filter: int | list[int] | None = None,
    proto_filter: str | list[str] | None = None,
) -> tuple:
    """Build the OpenSearch query body and request params.

    datasets: list of event.dataset values, or ["all"] to omit the filter.
    time_from/time_to: absolute ISO timestamps; when both are set they
        override the relative *time_range* parameter.
    """
    if time_from and time_to:
        ts_clause = {"range": {"@timestamp": {"gte": time_from, "lte": time_to}}}
    else:
        ts_clause = {"range": {"@timestamp": {"gte": time_range, "lte": "now"}}}
    must_clauses: list = [ts_clause]

    if datasets and datasets != ["all"]:
        must_clauses.append({"terms": {"event.dataset": datasets}})

    if sensors:
        must_clauses.append({"terms": {"host.name": sensors}})

    if src_ip_filter:
        if isinstance(src_ip_filter, list):
            must_clauses.append({"terms": {"source.ip": src_ip_filter}})
        else:
            must_clauses.append({"term": {"source.ip": src_ip_filter}})

    if dest_ip_filter:
        if isinstance(dest_ip_filter, list):
            must_clauses.append({"terms": {"destination.ip": dest_ip_filter}})
        else:
            must_clauses.append({"term": {"destination.ip": dest_ip_filter}})

    if src_port_filter is not None:
        if isinstance(src_port_filter, list):
            must_clauses.append({"terms": {"source.port": src_port_filter}})
        else:
            must_clauses.append({"term": {"source.port": src_port_filter}})

    if dest_port_filter is not None:
        if isinstance(dest_port_filter, list):
            must_clauses.append({"terms": {"destination.port": dest_port_filter}})
        else:
            must_clauses.append({"term": {"destination.port": dest_port_filter}})

    if proto_filter:
        if isinstance(proto_filter, list):
            must_clauses.append({"terms": {"network.transport": proto_filter}})
        else:
            must_clauses.append({"term": {"network.transport": proto_filter}})

    if any_ip_filter:
        must_clauses.append(
            {
                "bool": {
                    "should": [
                        {"term": {"source.ip": any_ip_filter}},
                        {"term": {"destination.ip": any_ip_filter}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        )

    if direction:
        must_clauses.append({"term": {"network.direction": direction}})

    must_clauses.extend(extra_must)

    effective_must_not = list(must_not)
    if public_only:
        effective_must_not.append(_PRIVATE_CIDR_MUST_NOT)

    body: dict = {
        "size": limit,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": must_clauses,
                "must_not": effective_must_not,
            }
        },
        "_source": source_fields,
    }
    if sort:
        body["sort"] = [{"@timestamp": {"order": "desc"}}]

    params = {
        "path": f"{INDEX}/_search?timeout=30s",
        "method": "POST",
    }

    return body, params
