"""JA4 fingerprint decoder — human-readable labels from JA4 hash prefixes."""

from __future__ import annotations

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
    """Decode a JA4 hash prefix into a human-readable summary.

    Example: ``t13d1516h2_...`` → ``TCP TLS1.3 HTTP/2 (15c/16e)``
    """
    if not ja4 or len(ja4) < 10:
        return ja4
    prefix = ja4.split("_")[0]
    proto = _PROTO.get(prefix[0], prefix[0])
    tls = _TLS.get(prefix[1:3], f"v{prefix[1:3]}")
    # sni = _SNI.get(prefix[3], "")  # not very useful to display
    ciphers = prefix[4:6] if len(prefix) >= 6 else "?"
    extensions = prefix[6:8] if len(prefix) >= 8 else "?"
    alpn = _ALPN.get(prefix[8:10], prefix[8:10]) if len(prefix) >= 10 else ""

    parts = [proto, tls]
    if alpn:
        parts.append(alpn)
    parts.append(f"({ciphers}c/{extensions}e)")
    return " ".join(parts)
