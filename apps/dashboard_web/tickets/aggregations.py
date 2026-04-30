"""Ticket aggregation functions for the dashboard — wraps mantis_explorer data."""

from apps.mantis_explorer.data import (
    compute_escalation_data,
    compute_global_stats,
    compute_timeline_data,
    get_report,
)


def agg_tickets(since: str = "", until: str = "") -> dict:
    """All ticket dashboard data in one call."""
    report = get_report(since, until)
    return {
        "stats": compute_global_stats(report),
        "timeline": compute_timeline_data(report),
        "escalation": compute_escalation_data(report),
    }
