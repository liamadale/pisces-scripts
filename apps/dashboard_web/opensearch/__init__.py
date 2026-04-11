from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.opensearch.aggregations import (
    agg_opensearch_protocols,
    agg_opensearch_sensors,
    agg_opensearch_top_ips,
)
from apps.dashboard_web.opensearch.malcolm import get_all_panels

bp = Blueprint("opensearch", __name__, template_folder="templates")


@bp.route("/api/dashboard/opensearch")
def section():
    time_range = request.args.get("time_range", "now-24h")
    cached = dcache.get("opensearch", {"time_range": time_range})
    if cached is not None:
        return cached
    try:
        data = {
            "protocols": agg_opensearch_protocols(time_range),
            "sensors": agg_opensearch_sensors(time_range),
            "top_ips": agg_opensearch_top_ips(time_range),
        }
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("opensearch/section.html", data=data, time_range=time_range)
    dcache.put("opensearch", {"time_range": time_range}, html)
    return html


@bp.route("/api/dashboard/opensearch/malcolm")
def malcolm():
    time_range = request.args.get("time_range", "now-24h")
    cached = dcache.get("malcolm_grid", {"time_range": time_range})
    if cached is not None:
        return cached
    try:
        panels = get_all_panels(time_range)
        error = None
    except Exception as exc:
        panels = {}
        error = str(exc)
    html = render_template(
        "opensearch/malcolm_grid.html",
        panels=panels,
        error=error,
        time_range=time_range,
    )
    if not error:
        dcache.put("malcolm_grid", {"time_range": time_range}, html)
    return html
