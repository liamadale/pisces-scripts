"""In-memory TTL cache for dashboard aggregation results.

Keyed on (section, time_range); stores rendered HTML partials so repeat tab
opens within a session skip backend queries entirely.

TTL defaults to 600 s; override with PISCES_DASHBOARD_CACHE_TTL env var.
Thread-safe via a Lock (Flask runs with threaded=True).
"""

import hashlib
import json
import os
import time
from threading import Lock

TTL = int(os.environ.get("PISCES_DASHBOARD_CACHE_TTL", 600))

_store: dict[str, tuple[float, object]] = {}
_lock = Lock()


def _key(section: str, params: dict) -> str:
    payload = json.dumps({"section": section, **params}, sort_keys=True)
    return hashlib.md5(payload.encode()).hexdigest()


def get(section: str, params: dict) -> object | None:
    """Return cached value if still within TTL, else None."""
    k = _key(section, params)
    with _lock:
        entry = _store.get(k)
        if entry and time.time() - entry[0] < TTL:
            return entry[1]
        return None


def put(section: str, params: dict, value: object) -> None:
    k = _key(section, params)
    with _lock:
        _store[k] = (time.time(), value)


def invalidate() -> None:
    """Clear all cached entries."""
    with _lock:
        _store.clear()


def stats() -> dict:
    """Return {entries, oldest_s} for the debug endpoint."""
    with _lock:
        now = time.time()
        ages = [now - v[0] for v in _store.values()]
        return {
            "entries": len(ages),
            "oldest_s": round(max(ages), 1) if ages else 0,
        }
