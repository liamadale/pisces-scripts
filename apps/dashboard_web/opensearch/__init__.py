from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.opensearch.aggregations import (
    agg_conn_volume_over_time,
    agg_notice_over_time,
    agg_opensearch_sensors,
    agg_opensearch_top_ips,
    agg_suricata_over_time,
    parse_sensors,
)
from apps.dashboard_web.opensearch.malcolm import get_all_panels

bp = Blueprint("opensearch", __name__, template_folder="templates")


@bp.route("/api/dashboard/opensearch")
def section():
    time_range = request.args.get("time_range", "now-24h")
    sensor_raw = request.args.get("sensor", "")
    sensors = parse_sensors(sensor_raw)
    cache_key = {"time_range": time_range, "sensor": sensor_raw}
    cached = dcache.get("opensearch", cache_key)
    if cached is not None:
        return cached
    try:
        data = {
            "notice_over_time": agg_notice_over_time(time_range, sensors),
            "suricata_over_time": agg_suricata_over_time(time_range, sensors),
            "conn_over_time": agg_conn_volume_over_time(time_range, sensors),
            "sensors": agg_opensearch_sensors(time_range),
            "top_ips": agg_opensearch_top_ips(time_range, sensors),
        }
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("opensearch/section.html", data=data, time_range=time_range)
    dcache.put("opensearch", cache_key, html)
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
