"""Tickets dashboard section — escalation and volume from mantis_explorer."""

from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web import safe_date_param
from apps.dashboard_web.tickets.aggregations import agg_tickets

bp = Blueprint("tickets", __name__, template_folder="templates")


@bp.route("/api/dashboard/tickets")
def section() -> str:
    since = safe_date_param(request.args.get("since", ""))
    until = safe_date_param(request.args.get("until", ""))
    cache_key = {"since": since, "until": until}
    cached = dcache.get("tickets", cache_key)
    if cached is not None:
        return cached
    try:
        data = agg_tickets(since, until)
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("tickets/section.html", data=data)
    dcache.put("tickets", cache_key, html)
    return html
