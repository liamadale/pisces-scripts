from flask import Blueprint, render_template, request

from apps.dashboard_web import cache as dcache
from apps.dashboard_web.mantis.aggregations import (
    agg_mantis_attack_types,
    agg_mantis_infra_count,
    agg_mantis_timeline,
    agg_mantis_top_ips,
)

bp = Blueprint("mantis", __name__, template_folder="templates")


@bp.route("/api/dashboard/mantis")
def section():
    since = request.args.get("since", "")
    until = request.args.get("until", "")
    cache_key = {"since": since, "until": until}
    cached = dcache.get("mantis", cache_key)
    if cached is not None:
        return cached
    try:
        data = {
            "attack_types": agg_mantis_attack_types(since, until),
            "timeline": agg_mantis_timeline(since, until),
            "top_ips": agg_mantis_top_ips(since, until),
            "infra_count": agg_mantis_infra_count(),
        }
    except Exception as exc:
        data = {"error": str(exc)}
    html = render_template("mantis/section.html", data=data)
    dcache.put("mantis", cache_key, html)
    return html
