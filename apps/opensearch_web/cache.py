"""In-memory TTL cache for web-layer query results.

Keyed on (log_type, search_params); stores parsed + deduplicated records so
repeat page loads within a session skip OpenSearch entirely.

TTL defaults to 300 s; override with PISCES_CACHE_TTL env var.
Thread-safe via a Lock (Flask runs with threaded=True).
"""

import hashlib
import json
import os
import threading
import time
from threading import Lock

TTL = int(os.environ.get("PISCES_CACHE_TTL", 300))

_store: dict[str, tuple[float, list]] = {}
_lock = Lock()

# Single-flight: prevents duplicate in-flight queries for the same key.
_inflight: dict[str, threading.Event] = {}
_inflight_lock = Lock()


def _key(log_type: str, search_params: dict) -> str:
    payload = json.dumps({"log_type": log_type, **search_params}, sort_keys=True)
    return hashlib.md5(payload.encode()).hexdigest()


def raw_key(log_type: str, search_params: dict) -> str:
    """Return the cache key string (used for ETags and single-flight coordination)."""
    return _key(log_type, search_params)


def claim(key: str) -> threading.Event | None:
    """Try to become the leader for a cache miss. Returns an Event if leader, None if follower."""
    with _inflight_lock:
        if key in _inflight:
            return None
        event = threading.Event()
        _inflight[key] = event
        return event


def wait_inflight(key: str) -> None:
    """Block until the leader for this key finishes."""
    with _inflight_lock:
        event = _inflight.get(key)
    if event:
        event.wait()


def release(key: str) -> None:
    """Mark a key as done and wake any threads waiting on it."""
    with _inflight_lock:
        event = _inflight.pop(key, None)
    if event:
        event.set()


def get(log_type: str, search_params: dict) -> list | None:
    """Return cached records if still within TTL, else None."""
    k = _key(log_type, search_params)
    with _lock:
        entry = _store.get(k)
        if entry and time.time() - entry[0] < TTL:
            return entry[1]
        return None


def put(log_type: str, search_params: dict, records: list) -> None:
    k = _key(log_type, search_params)
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
