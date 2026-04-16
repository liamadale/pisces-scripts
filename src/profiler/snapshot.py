"""Profile snapshot storage and diffing for anomaly detection.

Saves DeviceProfile snapshots as JSON in data/profiles/<sensor>/<ip>.json.
Diffs the current profile against the stored baseline to flag changes.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.profiler.device_profiler import DeviceProfile

_BASE = Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
_PROFILES_DIR = _BASE / "data" / "profiles"


def _snapshot_path(ip: str, sensor: str) -> Path:
    """Return the path for a profile snapshot file."""
    safe_sensor = sensor.replace("/", "_").replace("\\", "_")
    safe_ip = ip.replace(":", "_")
    return _PROFILES_DIR / safe_sensor / f"{safe_ip}.json"


def save_snapshot(profile: DeviceProfile) -> Path:
    """Save a DeviceProfile as a JSON snapshot. Returns the file path."""
    path = _snapshot_path(profile.ip, profile.sensor)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(profile), indent=2, default=str))
    return path


def load_snapshot(ip: str, sensor: str) -> dict | None:
    """Load a previously saved snapshot. Returns None if not found."""
    path = _snapshot_path(ip, sensor)
    if not path.exists():
        return None
    return json.loads(path.read_text())


# ---------------------------------------------------------------------------
# Diff engine
# ---------------------------------------------------------------------------


def diff_profiles(current: DeviceProfile, baseline: dict) -> list[dict]:
    """Compare current profile against a stored baseline.

    Returns a list of change dicts, each with:
        category: str — what changed (e.g. "ja4_fingerprints", "role")
        change: str — "added", "removed", "changed"
        detail: str — human-readable description
    """
    changes: list[dict] = []
    cur = asdict(current)

    # Role change
    if cur["role"] != baseline.get("role"):
        changes.append(
            {
                "category": "role",
                "change": "changed",
                "detail": (f"{baseline.get('role', 'unknown')} → {cur['role']}"),
            }
        )

    # OS change
    if cur["os_family"] != baseline.get("os_family"):
        changes.append(
            {
                "category": "os_family",
                "change": "changed",
                "detail": (
                    f"{baseline.get('os_family') or 'unknown'} → {cur['os_family'] or 'unknown'}"
                ),
            }
        )

    # Set-based diffs for fingerprints and lists
    _diff_hash_list(
        changes,
        "ja4_fingerprints",
        baseline.get("ja4_fingerprints", []),
        cur.get("ja4_fingerprints", []),
    )
    _diff_hash_list(
        changes,
        "ja4t_fingerprints",
        baseline.get("ja4t_fingerprints", []),
        cur.get("ja4t_fingerprints", []),
    )
    _diff_hash_list(
        changes,
        "hassh_fingerprints",
        baseline.get("hassh_fingerprints", []),
        cur.get("hassh_fingerprints", []),
    )

    # Software changes
    _diff_set(
        changes,
        "software",
        set(baseline.get("software", [])),
        set(cur.get("software", [])),
    )

    # DNS domain changes (top domains by name)
    old_domains = {d["domain"] for d in baseline.get("dns_top_domains", [])}
    new_domains = {d["domain"] for d in cur.get("dns_top_domains", [])}
    _diff_set(changes, "dns_domains", old_domains, new_domains)

    # Inbound service changes (by port)
    old_ports = {s["port"] for s in baseline.get("inbound_services", [])}
    new_ports = {s["port"] for s in cur.get("inbound_services", [])}
    _diff_set(changes, "inbound_services", old_ports, new_ports)

    # User changes
    _diff_set(
        changes,
        "users",
        set(baseline.get("users", [])),
        set(cur.get("users", [])),
    )

    return changes


def _diff_hash_list(
    changes: list[dict],
    category: str,
    old_list: list[dict],
    new_list: list[dict],
) -> None:
    """Diff lists of {hash, count} dicts by hash key."""
    old_hashes = {item["hash"] for item in old_list}
    new_hashes = {item["hash"] for item in new_list}
    for h in new_hashes - old_hashes:
        changes.append(
            {
                "category": category,
                "change": "added",
                "detail": h,
            }
        )
    for h in old_hashes - new_hashes:
        changes.append(
            {
                "category": category,
                "change": "removed",
                "detail": h,
            }
        )


def _diff_set(
    changes: list[dict],
    category: str,
    old_set: set,
    new_set: set,
) -> None:
    """Diff two sets, emitting added/removed changes."""
    for item in new_set - old_set:
        changes.append(
            {
                "category": category,
                "change": "added",
                "detail": str(item),
            }
        )
    for item in old_set - new_set:
        changes.append(
            {
                "category": category,
                "change": "removed",
                "detail": str(item),
            }
        )
