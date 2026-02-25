"""Human-readable formatting helpers shared across queriers and the web UI."""


def fmt_bytes(b) -> str:
    """Format a byte count as a human-readable string (B/KB/MB/GB/TB/PB), or '—'."""
    if b is None:
        return "—"
    try:
        b = float(b)
    except (TypeError, ValueError):
        return "—"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(b) < 1000:
            return f"{b:.1f}{unit}"
        b /= 1000
    return f"{b:.1f}PB"


def fmt_dur(d) -> str:
    """Format a duration in seconds as ms/s/m, or '—' if absent."""
    if d is None:
        return "—"
    try:
        d = float(d)
    except (TypeError, ValueError):
        return str(d)
    if d < 1:
        return f"{d * 1000:.0f}ms"
    if d < 60:
        return f"{d:.1f}s"
    return f"{d / 60:.1f}m"
