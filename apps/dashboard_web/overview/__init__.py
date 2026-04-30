from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.opensearch.aggregations import parse_sensors
from apps.dashboard_web.overview.aggregations import agg_overview

bp = Blueprint("overview", __name__, template_folder="templates")


@bp.route("/api/dashboard/overview")
def section():
    time_range = request.args.get("time_range", "now-24h")
    sensor_raw = request.args.get("sensor", "")
    sensors = parse_sensors(sensor_raw)
    cache_key = {"time_range": time_range, "sensor": sensor_raw}
    cached = dcache.get("overview", cache_key)
    if cached is not None:
        return cached
    try:
        data = agg_overview(time_range, sensors=sensors)
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("overview/section.html", data=data, time_range=time_range)
    dcache.put("overview", cache_key, html)
    return html
