"""In-memory TTL cache for Kibana web-layer query results.

TTL defaults to 300 s; override with PISCES_CACHE_TTL env var.
Thread-safe via a Lock (Flask runs with threaded=True).
"""

import hashlib
import json
import os
import time
from threading import Lock

TTL = int(os.environ.get("PISCES_CACHE_TTL", 300))

_store: dict[str, tuple[float, list]] = {}
_lock = Lock()


def _key(cache_type: str, search_params: dict) -> str:
    payload = json.dumps({"cache_type": cache_type, **search_params}, sort_keys=True)
    return hashlib.md5(payload.encode()).hexdigest()


def get(cache_type: str, search_params: dict) -> list | None:
    """Return cached records if still within TTL, else None."""
    k = _key(cache_type, search_params)
    with _lock:
        entry = _store.get(k)
        if entry and time.time() - entry[0] < TTL:
            return entry[1]
        return None


def put(cache_type: str, search_params: dict, records: list) -> None:
    k = _key(cache_type, search_params)
    with _lock:
        _store[k] = (time.time(), records)


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
