"""Software signature matching for device profiles.

Loads signatures from data/signatures/software.yaml and matches them
against DNS domains, HTTP user agents, and SSL SNI values from a
DeviceProfile.
"""

from __future__ import annotations

import os
from fnmatch import fnmatch
from typing import TYPE_CHECKING

import yaml

if TYPE_CHECKING:
    from src.profiler.device_profiler import DeviceProfile

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SIG_PATH = os.path.join(_BASE, "data", "signatures", "software.yaml")

_cached_sigs: list[dict] | None = None


def _load_signatures(path: str = _SIG_PATH) -> list[dict]:
    """Load and cache software signatures from YAML."""
    global _cached_sigs
    if _cached_sigs is not None:
        return _cached_sigs
    if not os.path.exists(path):
        return []
    with open(path) as f:
        _cached_sigs = yaml.safe_load(f) or []
    return _cached_sigs


def match_software(profile: DeviceProfile, sig_path: str = _SIG_PATH) -> list[str]:
    """Match software signatures against a DeviceProfile.

    Returns:
        Sorted list of detected software names.
    """
    sigs = _load_signatures(sig_path)
    domains = [d["domain"].lower() for d in profile.dns_top_domains]
    uas = [ua.lower() for ua in profile.user_agents]
    snis = [s.lower() for s in profile.ssl_sni_values]

    detected: set[str] = set()
    for sig in sigs:
        name = sig.get("name", "")
        for signal in sig.get("signals", []):
            stype = signal.get("type", "")
            pattern = signal.get("pattern", "").lower()
            requires = signal.get("requires", "")

            if requires and not any(requires.lower() in d.lower() for d in detected):
                continue

            matched = False
            if stype == "dns":
                matched = any(fnmatch(d, pattern) for d in domains)
            elif stype == "http_ua":
                matched = any(fnmatch(ua, pattern) for ua in uas)
            elif stype == "ssl_sni":
                matched = any(fnmatch(s, pattern) for s in snis)

            if matched:
                detected.add(name)
                break

    return sorted(detected)
