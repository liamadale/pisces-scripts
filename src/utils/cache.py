"""Disk-based JSON I/O with optional orjson acceleration.

Provides two API layers:

1. ``load_json`` / ``dump_json`` — general-purpose path-based JSON I/O used
   throughout the mantis pipeline.  Uses orjson when available, falls back to
   the stdlib ``json`` module transparently.

2. ``load_cache`` / ``save_cache`` / ``cache_path`` — legacy helpers used by
   the querier layer.  Built on top of the same orjson-aware core.
"""

import json
import os

# Project root — two dirname() calls up from src/utils/cache.py
_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import orjson as _orjson
except ImportError:  # pragma: no cover
    _orjson = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Core JSON I/O (orjson-accelerated when available)
# ---------------------------------------------------------------------------


def load_json(path: str) -> object:
    """Read and deserialise a JSON file, returning the parsed object."""
    if _orjson is not None:
        with open(path, "rb") as fh:
            return _orjson.loads(fh.read())
    with open(path) as fh:
        return json.load(fh)


def dump_json(data: object, path: str, *, indent: bool = True) -> None:
    """Serialise *data* to a JSON file at *path*."""
    if _orjson is not None:
        opt = _orjson.OPT_INDENT_2 if indent else 0
        with open(path, "wb") as fh:
            fh.write(_orjson.dumps(data, option=opt))
    else:
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2 if indent else None)


# ---------------------------------------------------------------------------
# Legacy querier-layer helpers (unchanged public API)
# ---------------------------------------------------------------------------


def cache_path(filename: str) -> str:
    """Return the full path for a cache file, creating the cache dir if needed."""
    cache_dir = os.path.join(_BASE, "data", "cache")
    os.makedirs(cache_dir, exist_ok=True)
    return os.path.join(cache_dir, filename)


def save_cache(data: dict, path: str) -> None:
    """Write *data* to *path* as JSON, silently ignoring write errors."""
    try:
        dump_json(data, path, indent=False)
    except OSError:
        pass


def load_cache(path: str) -> dict | None:
    """Load and return a JSON dict from *path*, or None on any error."""
    try:
        return load_json(path)  # type: ignore[return-value]
    except (OSError, json.JSONDecodeError, ValueError):
        return None
