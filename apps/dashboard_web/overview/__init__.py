from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.overview.aggregations import agg_overview

bp = Blueprint("overview", __name__, template_folder="templates")


@bp.route("/api/dashboard/overview")
def section():
    time_range = request.args.get("time_range", "now-24h")
    cached = dcache.get("overview", {"time_range": time_range})
    if cached is not None:
        return cached
    try:
        data = agg_overview(time_range)
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("overview/section.html", data=data, time_range=time_range)
    dcache.put("overview", {"time_range": time_range}, html)
    return html
