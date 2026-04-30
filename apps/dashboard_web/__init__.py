"""PISCES Dashboard web application package."""

from datetime import date


def safe_date_param(value: str) -> str:
    """Validate a date query parameter, returning '' for invalid values.

    Prevents user-supplied strings from reaching exception messages
    (reflected XSS via error rendering).
    """
    v = value.strip()
    if not v:
        return ""
    try:
        date.fromisoformat(v)
        return v
    except ValueError:
        return ""
