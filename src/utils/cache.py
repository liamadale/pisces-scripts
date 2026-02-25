"""Disk-based JSON response cache shared across queriers."""

import json
import os

# Project root — two dirname() calls up from src/utils/cache.py
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def cache_path(filename: str) -> str:
    """Return the full path for a cache file, creating the cache dir if needed."""
    cache_dir = os.path.join(_BASE, "data", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, filename)


def save_cache(data: dict, path: str) -> None:
    """Write *data* to *path* as JSON, silently ignoring write errors."""
    try:
        with open(path, "w") as fh:
            json.dump(data, fh)
    except OSError:
        pass


def load_cache(path: str) -> dict | None:
    """Load and return a JSON dict from *path*, or None on any error."""
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None
