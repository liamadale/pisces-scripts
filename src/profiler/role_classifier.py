"""Role classification and OS detection for device profiles.

Pure logic — operates on a populated DeviceProfile, no I/O.
"""

from __future__ import annotations

from fnmatch import fnmatch
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.profiler.device_profiler import DeviceProfile

# ---------------------------------------------------------------------------
# Role heuristics — weighted signal definitions
# ---------------------------------------------------------------------------

# Each role maps to a list of (weight, check_fn) tuples.
# check_fn takes a DeviceProfile and returns True if the signal is present.
# Confidence = sum(matched weights) / sum(all weights).


def _has_inbound_port(profile: DeviceProfile, port: int) -> bool:
    return any(s["port"] == port for s in profile.inbound_services)


def _has_inbound_proto(profile: DeviceProfile, proto: str) -> bool:
    return any(proto in s["app_proto"] for s in profile.inbound_services)


def _has_dns_match(profile: DeviceProfile, pattern: str) -> bool:
    return any(fnmatch(d["domain"].lower(), pattern) for d in profile.dns_top_domains)


def _has_dns_or_http_match(profile: DeviceProfile, pattern: str) -> bool:
    """Match against DNS domains or HTTP host headers."""
    if _has_dns_match(profile, pattern):
        return True
    return any(fnmatch(h["host"].lower(), pattern) for h in profile.http_top_hosts)


ROLE_HEURISTICS: dict[str, list[tuple[float, str, object]]] = {
    "domain_controller": [
        (0.15, "DNS inbound", lambda p: _has_inbound_port(p, 53)),
        (0.15, "LDAP inbound", lambda p: _has_inbound_port(p, 389)),
        (0.15, "Kerberos inbound", lambda p: _has_inbound_port(p, 88)),
        (0.15, "DCE/RPC inbound", lambda p: _has_inbound_proto(p, "dce_rpc")),
        (0.15, "SMB inbound", lambda p: _has_inbound_port(p, 445)),
        (0.10, "NTP outbound", lambda p: 123 in p.dest_port_distribution),
        (0.10, "Windows telemetry DNS", lambda p: _has_dns_or_http_match(p, "*.windowsupdate.com")),
        (0.05, "DC replication", lambda p: _has_inbound_port(p, 3268)),
    ],
    "file_server": [
        (0.30, "SMB inbound", lambda p: _has_inbound_port(p, 445)),
        (
            0.20,
            "High SMB count",
            lambda p: any(s["count"] > 50 for s in p.inbound_services if s["port"] == 445),
        ),
        (0.20, "Shares hosted", lambda p: len(p.smb_shares_hosted) > 0),
        (
            0.15,
            "Low outbound diversity",
            lambda p: _has_inbound_port(p, 445) and p.unique_dest_count < 20,
        ),
        (
            0.15,
            "No DC services",
            lambda p: (
                _has_inbound_port(p, 445)
                and not (_has_inbound_port(p, 53) and _has_inbound_port(p, 88))
            ),
        ),
    ],
    "workstation": [
        (0.25, "Low inbound", lambda p: p.unique_dest_count > 0 and len(p.inbound_services) <= 2),
        (0.20, "Browser UA", lambda p: any("mozilla" in ua.lower() for ua in p.user_agents)),
        (0.15, "WPAD DNS", lambda p: _has_dns_match(p, "wpad*")),
        (0.15, "Windows Update", lambda p: _has_dns_or_http_match(p, "*.windowsupdate.com")),
        (0.15, "High outbound diversity", lambda p: p.unique_dest_count > 20),
        (0.10, "Multiple JA4", lambda p: len(p.ja4_fingerprints) >= 3),
    ],
    "print_server": [
        (0.40, "Port 9100 inbound", lambda p: _has_inbound_port(p, 9100)),
        (0.30, "Port 515 or 631", lambda p: _has_inbound_port(p, 515) or _has_inbound_port(p, 631)),
        (0.30, "Low outbound", lambda p: _has_inbound_port(p, 9100) and p.unique_dest_count < 10),
    ],
    "linux_server": [
        (0.35, "SSH inbound", lambda p: p.ssh_inbound),
        (
            0.20,
            "No Windows DNS",
            lambda p: p.ssh_inbound and not _has_dns_match(p, "*.windowsupdate.com"),
        ),
        (0.15, "No WPAD", lambda p: p.ssh_inbound and not _has_dns_match(p, "wpad*")),
        (0.15, "SSH server version", lambda p: len(p.ssh_server_versions) > 0),
        (
            0.15,
            "No browser UA",
            lambda p: p.ssh_inbound and not any("mozilla" in ua.lower() for ua in p.user_agents),
        ),
    ],
    "network_appliance": [
        (0.30, "NTP inbound", lambda p: _has_inbound_port(p, 123)),
        (0.30, "SNMP inbound", lambda p: _has_inbound_port(p, 161)),
        (
            0.20,
            "Very few protocols",
            lambda p: len(p.inbound_services) > 0 and len(p.protocol_mix) <= 2,
        ),
        (
            0.20,
            "No DNS queries",
            lambda p: len(p.inbound_services) > 0 and len(p.dns_top_domains) == 0,
        ),
    ],
}


def classify_role(profile: DeviceProfile) -> tuple[str, float]:
    """Classify device role using weighted heuristics.

    Returns:
        (role, confidence) where confidence is 0.0–1.0.
    """
    best_role = "unknown"
    best_confidence = 0.0

    for role, signals in ROLE_HEURISTICS.items():
        matched = sum(w for w, _, fn in signals if fn(profile))
        total = sum(w for w, _, _ in signals)
        confidence = matched / total if total > 0 else 0.0
        if confidence > best_confidence:
            best_confidence = confidence
            best_role = role

    return best_role, round(best_confidence, 2)


# ---------------------------------------------------------------------------
# OS detection — multi-signal, layered
# ---------------------------------------------------------------------------

_WINDOWS_DNS = [
    "*.windowsupdate.com",
    "*.update.microsoft.com",
    "settings-win.data.microsoft.com",
    "wpad*",
]
_MACOS_DNS = [
    "*.apple.com",
    "configuration.apple.com",
    "mesu.apple.com",
]
_LINUX_DNS = [
    "connectivity-check.ubuntu.com",
    "changelogs.ubuntu.com",
    "*.fedoraproject.org",
]


def detect_os(profile: DeviceProfile) -> str | None:
    """Detect OS family from DNS patterns, HTTP UA OS, and SSH versions.

    Returns:
        OS family string (e.g. "windows", "linux", "macos") or None.
    """
    # Highest confidence: pre-parsed UA OS from Malcolm
    for os_name in profile.user_agent_os:
        lower = os_name.lower()
        if "windows" in lower:
            return "windows"
        if "mac" in lower or "ios" in lower:
            return "macos"
        if "linux" in lower or "ubuntu" in lower:
            return "linux"

    # DNS pattern matching
    domains = [d["domain"].lower() for d in profile.dns_top_domains]
    http_hosts = [h["host"].lower() for h in profile.http_top_hosts]
    all_names = domains + http_hosts
    for name in all_names:
        if any(fnmatch(name, p) for p in _WINDOWS_DNS):
            return "windows"
    for name in all_names:
        if any(fnmatch(name, p) for p in _MACOS_DNS):
            return "macos"
    for name in all_names:
        if any(fnmatch(name, p) for p in _LINUX_DNS):
            return "linux"

    # SSH version strings
    for ver in profile.ssh_server_versions:
        lower = ver.lower()
        if "ubuntu" in lower or "debian" in lower:
            return "linux"
        if "freebsd" in lower:
            return "linux"

    for ver in profile.ssh_client_versions:
        if "putty" in ver.lower():
            return "windows"

    return None
