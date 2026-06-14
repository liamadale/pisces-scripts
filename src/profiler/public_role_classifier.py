"""Public IP role classification — weighted heuristics.

Pure logic — operates on a populated PublicIPProfile, no I/O.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.profiler.public_ip_profiler import PublicIPProfile


def _has_service(profile: PublicIPProfile, port: int) -> bool:
    return any(s["port"] == port for s in profile.services)


def _has_known_issuer(profile: PublicIPProfile) -> bool:
    known = ("let's encrypt", "digicert", "comodo", "globalsign", "sectigo")
    return any(any(k in iss.lower() for k in known) for iss in profile.ssl_issuers)


def _low_bytes_ratio(profile: PublicIPProfile) -> bool:
    if profile.internal_targets_count == 0:
        return False
    total = profile.bytes_to + profile.bytes_from
    return (total / profile.internal_targets_count) < 1024


_MAIL_PORTS = {25, 465, 587, 993, 143}


PUBLIC_ROLE_HEURISTICS: dict[str, list[tuple[float, str, object]]] = {
    "web_server": [
        (0.30, "HTTPS service", lambda p: _has_service(p, 443)),
        (0.20, "HTTP service", lambda p: _has_service(p, 80)),
        (0.20, "Multiple clients", lambda p: p.internal_client_count > 5),
        (0.15, "Valid TLS cert", lambda p: _has_known_issuer(p)),
        (0.15, "Has reverse DNS", lambda p: len(p.reverse_dns) > 0),
    ],
    "scanner": [
        (0.30, "High target count", lambda p: p.internal_targets_count > 20),
        (
            0.25,
            "Many ports probed",
            lambda p: len(p.inbound_ports_targeted) > 5,
        ),
        (
            0.25,
            "Inbound conn from IP",
            lambda p: p.internal_targets_count > 0,
        ),
        (0.20, "Low bytes per target", lambda p: _low_bytes_ratio(p)),
    ],
    "cdn_node": [
        (
            0.35,
            "Known CDN org",
            lambda p: p.org and p.org.get("category") == "cdn",
        ),
        (0.25, "HTTPS primary", lambda p: _has_service(p, 443)),
        (0.20, "High client count", lambda p: p.internal_client_count > 20),
        (0.20, "Multiple domains", lambda p: len(p.reverse_dns) > 2),
    ],
    "mail_server": [
        (
            0.35,
            "Mail port",
            lambda p: any(_has_service(p, pt) for pt in _MAIL_PORTS),
        ),
        (
            0.30,
            "MX-related DNS",
            lambda p: any(
                "mx" in d["domain"].lower() or "mail" in d["domain"].lower() for d in p.reverse_dns
            ),
        ),
        (0.20, "Has reverse DNS", lambda p: len(p.reverse_dns) > 0),
        (0.15, "Valid TLS cert", lambda p: _has_known_issuer(p)),
    ],
    "dns_server": [
        (0.40, "Port 53 service", lambda p: _has_service(p, 53)),
        (0.30, "Many clients", lambda p: p.internal_client_count > 10),
        (
            0.30,
            "No web ports",
            lambda p: _has_service(p, 53) and not _has_service(p, 443),
        ),
    ],
    "ssh_server": [
        (0.40, "Port 22 service", lambda p: _has_service(p, 22)),
        (
            0.30,
            "SSH server version",
            lambda p: len(p.ssh_server_versions) > 0,
        ),
        (
            0.30,
            "Few clients",
            lambda p: _has_service(p, 22) and p.internal_client_count <= 5,
        ),
    ],
    "vpn_endpoint": [
        (
            0.30,
            "VPN ports",
            lambda p: any(_has_service(p, pt) for pt in (1194, 500, 4500, 51820)),
        ),
        (
            0.30,
            "High bytes bidirectional",
            lambda p: (p.bytes_to + p.bytes_from) > 10_000_000,
        ),
        (0.20, "Few clients", lambda p: len(p.services) > 0 and p.internal_client_count <= 3),
        (0.20, "HTTPS or VPN port", lambda p: _has_service(p, 443)),
    ],
    "c2_suspect": [
        (
            0.30,
            "Self-signed cert",
            lambda p: len(p.ssl_subjects) > 0 and not _has_known_issuer(p),
        ),
        (0.25, "Unusual ports", lambda p: _has_unusual_ports(p)),
        (
            0.25,
            "Low client count",
            lambda p: 0 < p.internal_client_count <= 2,
        ),
        (
            0.20,
            "No reverse DNS",
            lambda p: len(p.services) > 0 and len(p.reverse_dns) == 0,
        ),
    ],
}

_COMMON_PORTS = {
    22,
    25,
    53,
    80,
    143,
    443,
    465,
    587,
    993,
    8080,
    8443,
    123,
    500,
    4500,
}


def _has_unusual_ports(profile: PublicIPProfile) -> bool:
    return any(s["port"] not in _COMMON_PORTS for s in profile.services)


def classify_public_role(
    profile: PublicIPProfile,
) -> tuple[str, float]:
    """Classify public IP role using weighted heuristics.

    Returns:
        (role, confidence) where confidence is 0.0–1.0.
    """
    best_role = "unknown"
    best_confidence = 0.0

    for role, signals in PUBLIC_ROLE_HEURISTICS.items():
        matched = sum(w for w, _, fn in signals if fn(profile))
        total = sum(w for w, _, _ in signals)
        confidence = matched / total if total > 0 else 0.0
        if confidence > best_confidence:
            best_confidence = confidence
            best_role = role

    return best_role, round(best_confidence, 2)
