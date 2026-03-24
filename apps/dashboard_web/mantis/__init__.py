from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.mantis.aggregations import (
    agg_mantis_attack_types,
    agg_mantis_blocklists,
    agg_mantis_infra_count,
    agg_mantis_timeline,
    agg_mantis_top_ips,
)

bp = Blueprint("mantis", __name__, template_folder="templates")


@bp.route("/api/dashboard/mantis")
def section():
    time_range = request.args.get("time_range", "now-24h")
    cached = dcache.get("mantis", {"time_range": time_range})
    if cached is not None:
        return cached
    try:
        data = {
            "attack_types": agg_mantis_attack_types(),
            "timeline": agg_mantis_timeline(),
            "blocklists": agg_mantis_blocklists(),
            "top_ips": agg_mantis_top_ips(),
            "infra_count": agg_mantis_infra_count(),
        }
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("mantis/section.html", data=data, time_range=time_range)
    dcache.put("mantis", {"time_range": time_range}, html)
    return html
