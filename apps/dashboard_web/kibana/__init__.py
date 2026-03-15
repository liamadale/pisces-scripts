from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.kibana.aggregations import (
    agg_kibana_severity,
    agg_kibana_signatures,
    agg_kibana_cities,
)

bp = Blueprint("kibana", __name__, template_folder="templates")


@bp.route("/api/dashboard/kibana")
def section():
    time_range = request.args.get("time_range", "now-24h")
    cached = dcache.get("kibana", {"time_range": time_range})
    if cached is not None:
        return cached
    try:
        data = {
            "severity":   agg_kibana_severity(time_range),
            "signatures": agg_kibana_signatures(time_range),
            "cities":     agg_kibana_cities(time_range),
        }
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("kibana/section.html", data=data, time_range=time_range)
    dcache.put("kibana", {"time_range": time_range}, html)
    return html
