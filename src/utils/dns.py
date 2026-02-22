"""
Shared DNS override for cyberrangepoulsbo.com.

Patches socket.getaddrinfo so that any hostname ending in
cyberrangepoulsbo.com resolves via the internal nameserver at 192.168.168.1
rather than public DNS.  Safe to call multiple times (no-op after first call).
"""

import socket
import subprocess
import re

_dns_configured = False
_original_getaddrinfo = socket.getaddrinfo

_DOMAIN = "cyberrangepoulsbo.com"
_NAMESERVER = "192.168.168.1"


def _nslookup(hostname: str) -> str | None:
    """Query the internal nameserver for a hostname. Returns the first A record IP or None."""
    try:
        result = subprocess.run(
            ["nslookup", hostname, _NAMESERVER],
            capture_output=True,
            text=True,
            timeout=5,
        )
        # Parse "Address: x.x.x.x" lines, skip the server line
        addresses = re.findall(r"Address:\s+([\d.]+)", result.stdout)
        # The first address is the nameserver itself; subsequent are answers
        answers = [a for a in addresses if a != _NAMESERVER]
        return answers[0] if answers else None
    except Exception:
        return None


def _patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if isinstance(host, str) and host.endswith(_DOMAIN):
        resolved = _nslookup(host)
        if resolved:
            host = resolved
    return _original_getaddrinfo(host, port, family, type, proto, flags)


def setup_dns() -> None:
    """Patch socket.getaddrinfo to resolve cyberrangepoulsbo.com via internal DNS.

    Idempotent — safe to call multiple times.
    """
    global _dns_configured
    if _dns_configured:
        return
    socket.getaddrinfo = _patched_getaddrinfo
    _dns_configured = True
