"""JA4 fingerprint decoder — human-readable labels from JA4 hash prefixes.

Uses the JA4DB community database (ja4db.com) for application identification
when available, with prefix decoding as fallback.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import requests

_PROTO = {"t": "TCP", "q": "QUIC"}
_TLS = {"10": "TLS 1.0", "11": "TLS 1.1", "12": "TLS 1.2", "13": "TLS 1.3", "00": "unknown"}
_ALPN = {
    "h2": "HTTP/2",
    "h1": "HTTP/1.1",
    "dt": "DNS-over-TLS",
    "00": "",
}

_CACHE_DIR = (
    Path(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))) / "data"
)
_JA4DB_PATH = _CACHE_DIR / "ja4db.json"
_JA4DB_URL = "https://ja4db.com/api/download/"

_lookup: dict[str, str] | None = None
_partial_lookup: dict[str, str] | None = None


def _load_ja4db() -> dict[str, str]:
    """Load JA4DB into hash→label lookup dicts. Downloads on first use."""
    global _lookup, _partial_lookup
    if _lookup is not None:
        return _lookup

    if not _JA4DB_PATH.exists():
        try:
            resp = requests.get(_JA4DB_URL, timeout=30)
            resp.raise_for_status()
            _CACHE_DIR.mkdir(parents=True, exist_ok=True)
            _JA4DB_PATH.write_bytes(resp.content)
        except Exception:
            _lookup, _partial_lookup = {}, {}
            return _lookup

    try:
        entries = json.loads(_JA4DB_PATH.read_text())
    except Exception:
        _lookup, _partial_lookup = {}, {}
        return _lookup

    _lookup, _partial_lookup = {}, {}
    for entry in entries:
        label = entry.get("application") or entry.get("device") or entry.get("library")
        if not label:
            continue
        os_info = entry.get("os") or ""
        full_label = f"{label} ({os_info})" if os_info and os_info != "Other" else label
        for key in (
            "ja4_fingerprint",
            "ja4h_fingerprint",
            "ja4t_fingerprint",
            "ja4s_fingerprint",
        ):
            fp = entry.get(key)
            if not fp:
                continue
            if fp not in _lookup:
                _lookup[fp] = full_label
            # Partial key: first two sections for fuzzy matching
            parts = fp.split("_")
            if len(parts) >= 2:
                partial = f"{parts[0]}_{parts[1]}"
                if partial not in _partial_lookup:
                    _partial_lookup[partial] = label
    return _lookup


def lookup_ja4(ja4: str) -> str | None:
    """Look up a JA4 hash in the JA4DB database.

    Tries exact match first, then partial match on the first two sections
    (prefix + cipher hash) which identifies the application family even
    when the extension hash differs across OS/version.

    Returns:
        Application/device label, or None if not found.
    """
    db = _load_ja4db()
    exact = db.get(ja4)
    if exact:
        return exact
    # Partial: match on prefix_cipherhash
    parts = ja4.split("_")
    if len(parts) >= 2 and _partial_lookup:
        return _partial_lookup.get(f"{parts[0]}_{parts[1]}")
    return None


_PROTO = {"t": "TCP", "q": "QUIC"}
_TLS = {"10": "TLS 1.0", "11": "TLS 1.1", "12": "TLS 1.2", "13": "TLS 1.3", "00": "unknown"}
_SNI = {"d": "domain", "i": "IP"}
_ALPN = {
    "h2": "HTTP/2",
    "h1": "HTTP/1.1",
    "dt": "DNS-over-TLS",
    "00": "",
}


def decode_ja4(ja4: str) -> str:
    """Decode a JA4 hash into a human-readable summary.

    Checks JA4DB for a known application match first. Falls back to
    prefix decoding if not found.

    Example: ``t13d1516h2_...`` → ``Chrome (Windows)`` or ``TCP TLS1.3 HTTP/2 (15c/16e)``
    """
    if not ja4 or len(ja4) < 10:
        return ja4

    # Try JA4DB lookup first
    db_label = lookup_ja4(ja4)
    if db_label:
        return db_label

    # Fallback: decode the prefix
    prefix = ja4.split("_")[0]
    proto = _PROTO.get(prefix[0], prefix[0])
    tls = _TLS.get(prefix[1:3], f"v{prefix[1:3]}")
    ciphers = prefix[4:6] if len(prefix) >= 6 else "?"
    extensions = prefix[6:8] if len(prefix) >= 8 else "?"
    alpn = _ALPN.get(prefix[8:10], prefix[8:10]) if len(prefix) >= 10 else ""

    parts = [proto, tls]
    if alpn:
        parts.append(alpn)
    parts.append(f"({ciphers}c/{extensions}e)")
    return " ".join(parts)
