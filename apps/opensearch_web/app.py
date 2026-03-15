"""Flask application factory and route definitions for PISCES Web UI."""

import json

from flask import Flask, render_template, request, abort

from src.querier.zeek_modules import MODULES
from src.querier.zeek_modules.base import TIME_RANGES, is_private
from src.utils.format import fmt_bytes, fmt_dur
from src.utils.ip_org import lookup_org
from apps.opensearch_web import cache as wcache
from apps.opensearch_web.queries import (
    MODULE_PARAM_KEYS,
    build_search_params_from_request,
    cached_run_query,
    run_cross_protocol_query,
)


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    # Register Jinja2 filters
    app.jinja_env.filters["fmt_bytes"] = fmt_bytes
    app.jinja_env.filters["fmt_dur"] = fmt_dur

    # Register Jinja2 globals
    app.jinja_env.globals["is_private"] = is_private
    app.jinja_env.globals["lookup_org"] = lookup_org
    app.jinja_env.globals["mantis_status_badge"] = lambda s: {
        "resolved": "badge-green", "closed": "badge-green",
        "new": "badge-blue", "acknowledged": "badge-blue",
    }.get(s, "badge-yellow")
    app.jinja_env.globals["mantis_sev_badge"] = lambda s: {
        "major": "badge-yellow", "critical": "badge-red",
        "minor": "badge-blue",
    }.get(s, "badge-gray")

    # Make TIME_RANGES and MODULES available to all templates
    @app.context_processor
    def inject_globals():
        return {
            "TIME_RANGES": TIME_RANGES,
            "MODULES": list(MODULES.keys()),
            "script_name": request.environ.get("SCRIPT_NAME", ""),
        }

    # ------------------------------------------------------------------
    # GET /  — cross-protocol IP matrix
    # ------------------------------------------------------------------
    @app.route("/")
    def overview():
        search_params = build_search_params_from_request(request)
        rows = run_cross_protocol_query(search_params)
        return render_template(
            "overview.html",
            rows=rows,
            search_params=search_params,
            log_types=list(MODULES.keys()),
        )

    # ------------------------------------------------------------------
    # GET /ip/<ip>  — all-protocol view for one IP
    # ------------------------------------------------------------------
    @app.route("/ip/<ip>")
    def ip_pivot(ip: str):
        search_params = build_search_params_from_request(request)
        search_params["src_ip"] = ip

        results: dict = {}
        for lt in MODULES:
            sp = dict(search_params)
            results[lt] = cached_run_query(lt, sp)

        return render_template(
            "ip_pivot.html",
            ip=ip,
            results=results,
            search_params=search_params,
            log_types=list(MODULES.keys()),
            MODULE_PARAM_KEYS=MODULE_PARAM_KEYS,
        )

    # ------------------------------------------------------------------
    # GET /log/<log_type>  — single-protocol drill-down
    # ------------------------------------------------------------------
    @app.route("/log/<log_type>")
    def log_view(log_type: str):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = MODULE_PARAM_KEYS.get(log_type, [])
        search_params = build_search_params_from_request(request, extra_keys)
        records = cached_run_query(log_type, search_params)
        return render_template(
            "log_view.html",
            log_type=log_type,
            records=records,
            search_params=search_params,
            extra_keys=extra_keys,
            detail_fields=mod.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # POST /api/search/<log_type>  — HTMX: re-run query, return table rows partial
    # ------------------------------------------------------------------
    @app.route("/api/search/<log_type>", methods=["POST"])
    def api_search(log_type: str):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = MODULE_PARAM_KEYS.get(log_type, [])
        search_params = build_search_params_from_request(request, extra_keys)
        records = cached_run_query(log_type, search_params)
        return render_template(
            "partials/log_rows.html",
            log_type=log_type,
            records=records,
            detail_fields=mod.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # GET /api/detail/<log_type>/<int:i>  — HTMX: expanded record detail
    # ------------------------------------------------------------------
    @app.route("/api/detail/<log_type>/<int:i>")
    def api_detail(log_type: str, i: int):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = MODULE_PARAM_KEYS.get(log_type, [])
        search_params = build_search_params_from_request(request, extra_keys)
        records = cached_run_query(log_type, search_params)
        if i < 1 or i > len(records):
            return "<tr><td colspan='99'>Record not found.</td></tr>", 404
        record = records[i - 1]
        return render_template(
            "partials/record_detail.html",
            record=record,
            detail_fields=mod.DETAIL_FIELDS,
            idx=i,
            log_type=log_type,
        )

    # ------------------------------------------------------------------
    # GET /api/filter/form  — HTMX: render inline filter creation form
    # ------------------------------------------------------------------
    @app.route("/api/filter/form")
    def api_filter_form():
        from src.querier.fp_manager import load_categories
        cats_data = load_categories()
        return render_template(
            "partials/filter_form.html",
            src_ip=request.args.get("src_ip", ""),
            dest_ip=request.args.get("dest_ip", ""),
            notice_note=request.args.get("notice_note", ""),
            log_type=request.args.get("log_type", ""),
            idx=request.args.get("idx", "0"),
            categories=cats_data.get("categories", {}),
        )

    # ------------------------------------------------------------------
    # POST /api/filter/create  — HTMX: write YAML clause, return result card
    # ------------------------------------------------------------------
    @app.route("/api/filter/create", methods=["POST"])
    def api_filter_create():
        from src.querier.fp_manager import (
            append_clauses_to_file, ensure_subcategory, filter_file_path,
        )
        category    = request.form.get("category", "").strip()
        subcategory = request.form.get("subcategory", "").strip()
        filter_type = request.form.get("filter_type", "")
        src_ip      = request.form.get("src_ip", "")
        dest_ip     = request.form.get("dest_ip", "")
        notice_note = request.form.get("notice_note", "")
        comment     = request.form.get("comment", "").strip()
        idx         = request.form.get("idx", "0")

        if not category or not subcategory:
            return render_template("partials/filter_result.html",
                                   success=False, error="Category and subcategory are required.",
                                   idx=idx)

        if filter_type == "src_ip":
            clause = {"term": {"src_ip": src_ip}}
        elif filter_type == "dest_ip":
            clause = {"term": {"dest_ip": dest_ip}}
        elif filter_type == "notice_src_ip_and_note":
            clause = {"bool": {"must": [
                {"term": {"src_ip": src_ip}},
                {"term": {"zeek.notice.note": notice_note}},
            ]}}
        else:
            return render_template("partials/filter_result.html",
                                   success=False, error=f"Unknown filter type: {filter_type!r}",
                                   idx=idx)

        if comment:
            clause["comment"] = comment

        try:
            path = filter_file_path(category, subcategory)
            append_clauses_to_file(path, [clause], author="web")
            ensure_subcategory(category, subcategory)
            return render_template("partials/filter_result.html",
                                   success=True, category=category, subcategory=subcategory,
                                   idx=idx)
        except Exception as exc:
            return render_template("partials/filter_result.html",
                                   success=False, error=str(exc), idx=idx)

    # ------------------------------------------------------------------
    # GET /api/mantis/search  — HTMX: search Mantis tickets, return card partial
    # ------------------------------------------------------------------
    @app.route("/api/mantis/search")
    def api_mantis_search():
        from src.mantis.mantis_search import search, sensor_to_project
        query = request.args.get("query", "").strip()
        idx = request.args.get("idx", "0")
        city = sensor_to_project(request.args.get("sensor", "all"))
        tickets = search(query, city=city) if query else []
        return render_template("partials/mantis_results.html",
                               tickets=tickets, query=query, idx=idx)

    # ------------------------------------------------------------------
    # Cache debug endpoints
    # ------------------------------------------------------------------
    @app.route("/api/cache/stats")
    def api_cache_stats():
        s = wcache.stats()
        return json.dumps({**s, "ttl": wcache.TTL}), 200, {"Content-Type": "application/json"}

    @app.route("/api/cache/clear", methods=["GET", "POST"])
    def api_cache_clear():
        wcache.invalidate()
        return "", 204

    # ------------------------------------------------------------------
    # GET /api/notice/summary  — HTMX: notice type frequency aggregation
    # ------------------------------------------------------------------
    @app.route("/api/notice/summary")
    def api_notice_summary():
        from src.querier.zeek_modules.base import (
            build_base_query, load_with_remap, query_opensearch, FILTERS_DIR,
        )
        mod = MODULES["notice"]
        search_params = build_search_params_from_request(request)

        must_not, _, _ = load_with_remap(FILTERS_DIR)
        sensor_val = search_params.get("sensor", "all")
        sensors = (
            [s.strip() for s in str(sensor_val).split(",")]
            if sensor_val and str(sensor_val).lower() != "all"
            else None
        )

        body, params = build_base_query(
            must_not=must_not,
            extra_must=[],
            source_fields=mod.SOURCE_FIELDS,
            limit=0,
            time_range=search_params.get("time_range", "now-24h"),
            sensors=sensors,
            datasets=mod.DATASETS,
            public_only=search_params.get("public_only", False),
            src_ip_filter=search_params.get("src_ip"),
            direction=search_params.get("direction"),
            min_risk_score=search_params.get("min_risk_score"),
        )
        body["size"] = 0
        body.pop("sort", None)
        body.pop("_source", None)
        body["aggs"] = {
            "note_types": {
                "terms": {
                    "field": "zeek.notice.note",
                    "size": 500,
                    "order": {"_count": "asc"},
                }
            }
        }

        raw = query_opensearch(body, params)
        buckets = []
        if raw:
            buckets = raw.get("aggregations", {}).get("note_types", {}).get("buckets", [])

        return render_template("partials/notice_summary.html", buckets=buckets)

    # ------------------------------------------------------------------
    # GET /api/sensor/summary  — HTMX: sensor activity aggregation
    # ------------------------------------------------------------------
    @app.route("/api/sensor/summary")
    def api_sensor_summary():
        from src.querier.zeek_modules.base import (
            build_base_query, query_opensearch,
        )
        search_params = build_search_params_from_request(request)

        body, params = build_base_query(
            must_not=[],
            extra_must=[],
            source_fields=[],
            limit=0,
            time_range=search_params.get("time_range", "now-24h"),
            sensors=None,
            datasets=["all"],
            public_only=False,
            src_ip_filter=None,
            direction=None,
            min_risk_score=None,
        )
        body["size"] = 0
        body.pop("sort", None)
        body.pop("_source", None)
        body["aggs"] = {
            "sensors": {
                "terms": {
                    "field": "host.name",
                    "size": 500,
                    "order": {"_count": "desc"},
                }
            }
        }

        raw = query_opensearch(body, params)
        buckets = []
        if raw:
            buckets = raw.get("aggregations", {}).get("sensors", {}).get("buckets", [])

        current_sensors = [
            s.strip()
            for s in search_params.get("sensor", "").split(",")
            if s.strip() and s.strip().lower() != "all"
        ]

        return render_template(
            "partials/sensor_summary.html",
            buckets=buckets,
            current_sensors=current_sensors,
        )

    # ------------------------------------------------------------------
    # POST /api/enrich/<ip>  — HTMX: run enrichment, return card partial
    # ------------------------------------------------------------------
    @app.route("/api/enrich/<ip>", methods=["POST"])
    def api_enrich(ip: str):
        if is_private(ip):
            return (
                '<p class="empty-note">'
                '<i class="fa-solid fa-house-lock"></i> Private IP — enrichment unavailable'
                '</p>'
            )
        from src.enricher.threat_intel import enrich_ip
        from src.enricher import greynoise, abuseipdb, shodan, virustotal

        result = enrich_ip(ip, offer_fp=False)

        urls = {
            "greynoise": greynoise.URL.format(ip=ip),
            "abuseipdb": abuseipdb.URL.format(ip=ip),
            "shodan": shodan.URL.format(ip=ip),
            "virustotal": virustotal.URL.format(ip=ip),
        }

        return render_template(
            "partials/enrich_card.html",
            ip=ip,
            result=result,
            urls=urls,
        )

    return app
