"""Shared Jinja2 globals and filters registered on all PISCES web apps."""

from flask import Flask

from src.querier.zeek_modules.base import is_private
from src.utils.format import fmt_bytes
from src.utils.ip_org import lookup_org


def register_shared_helpers(app: Flask) -> None:
    """Register shared Jinja2 globals and filters on a Flask app instance."""
    app.jinja_env.filters["fmt_bytes"] = fmt_bytes

    app.jinja_env.globals["is_private"] = is_private
    app.jinja_env.globals["lookup_org"] = lookup_org
    app.jinja_env.globals["role_icon"] = lambda role: {
        "domain_controller": "server",
        "file_server": "folder-open",
        "workstation": "desktop",
        "print_server": "print",
        "linux_server": "terminal",
        "network_appliance": "network-wired",
        "unknown": "circle-question",
    }.get(role, "circle-question")

    from src.profiler.ja4_decoder import decode_ja4

    app.jinja_env.globals["decode_ja4"] = decode_ja4
    app.jinja_env.globals["mantis_status_badge"] = lambda s: {
        "resolved": "badge-green",
        "closed": "badge-green",
        "new": "badge-blue",
        "acknowledged": "badge-blue",
    }.get(s, "badge-yellow")
    app.jinja_env.globals["mantis_sev_badge"] = lambda s: {
        "major": "badge-yellow",
        "critical": "badge-red",
        "minor": "badge-blue",
    }.get(s, "badge-gray")
