"""Flask application factory and route definitions for PISCES Kibana Web UI."""

import json

from flask import Flask, render_template, request, abort

from src.querier.kibana_module import TIME_RANGES, KibanaModule
from src.querier.zeek_modules.base import is_private
from src.utils.format import fmt_bytes
from src.utils.ip_org import lookup_org
from apps.kibana_web import cache as wcache
from apps.kibana_web.queries import (
    build_search_params_from_request,
    cached_run_alerts,
    cached_run_overview,
)

_module = KibanaModule()


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    app.jinja_env.filters["fmt_bytes"] = fmt_bytes

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

    @app.context_processor
    def inject_globals():
        return {"TIME_RANGES": TIME_RANGES}

    # ------------------------------------------------------------------
    # GET /  — IP × Severity overview matrix
    # ------------------------------------------------------------------
    @app.route("/")
    def overview():
        search_params = build_search_params_from_request(request)
        rows = cached_run_overview(search_params)
        return render_template("overview.html", rows=rows, search_params=search_params)

    # ------------------------------------------------------------------
    # GET /alerts  — full alert list
    # ------------------------------------------------------------------
    @app.route("/alerts")
    def alerts():
        search_params = build_search_params_from_request(request)
        records = cached_run_alerts(search_params)
        return render_template(
            "alerts.html",
            records=records,
            search_params=search_params,
            detail_fields=_module.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # GET /ip/<ip>  — all alerts for one source IP
    # ------------------------------------------------------------------
    @app.route("/ip/<ip>")
    def ip_pivot(ip: str):
        search_params = build_search_params_from_request(request)
        search_params["src_ip"] = ip
        records = cached_run_alerts(search_params)
        return render_template(
            "ip_pivot.html",
            ip=ip,
            records=records,
            search_params=search_params,
            detail_fields=_module.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # GET /signature/<sig>  — all alerts for one signature
    # ------------------------------------------------------------------
    @app.route("/signature/<path:sig>")
    def signature_view(sig: str):
        search_params = build_search_params_from_request(request)
        search_params["signature"] = sig
        records = cached_run_alerts(search_params)
        return render_template(
            "signature.html",
            sig=sig,
            records=records,
            search_params=search_params,
            detail_fields=_module.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # GET /city/<city>  — all alerts from one city/sensor
    # ------------------------------------------------------------------
    @app.route("/city/<city>")
    def city_view(city: str):
        search_params = build_search_params_from_request(request)
        search_params["cities"] = city
        records = cached_run_alerts(search_params)
        return render_template(
            "alerts.html",
            records=records,
            search_params=search_params,
            detail_fields=_module.DETAIL_FIELDS,
            page_title=f"Alerts — {city}",
        )

    # ------------------------------------------------------------------
    # POST /api/search  — HTMX: re-run query, return alert_rows partial
    # ------------------------------------------------------------------
    @app.route("/api/search", methods=["POST"])
    def api_search():
        search_params = build_search_params_from_request(request)
        records = cached_run_alerts(search_params)
        return render_template(
            "partials/alert_rows.html",
            records=records,
            detail_fields=_module.DETAIL_FIELDS,
        )

    # ------------------------------------------------------------------
    # GET /api/detail/<int:i>  — HTMX: expanded record detail
    # ------------------------------------------------------------------
    @app.route("/api/detail/<int:i>")
    def api_detail(i: int):
        search_params = build_search_params_from_request(request)
        records = cached_run_alerts(search_params)
        if i < 1 or i > len(records):
            return "<tr><td colspan='99'>Record not found.</td></tr>", 404
        record = records[i - 1]
        return render_template(
            "partials/record_detail.html",
            record=record,
            detail_fields=_module.DETAIL_FIELDS,
            idx=i,
        )

    # ------------------------------------------------------------------
    # GET /api/filter/form  — HTMX: filter creation form
    # ------------------------------------------------------------------
    @app.route("/api/filter/form")
    def api_filter_form():
        from src.querier.fp_manager import load_categories
        cats_data = load_categories()
        return render_template(
            "partials/filter_form.html",
            src_ip=request.args.get("src_ip", ""),
            dest_ip=request.args.get("dest_ip", ""),
            signature=request.args.get("signature", ""),
            idx=request.args.get("idx", "0"),
            categories=cats_data.get("categories", {}),
        )

    # ------------------------------------------------------------------
    # POST /api/filter/create  — HTMX: write YAML filter
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
        signature   = request.form.get("signature", "")
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
        elif filter_type == "signature_and_src":
            clause = {"bool": {"must": [
                {"term": {"src_ip": src_ip}},
                {"match_phrase": {"alert.signature": signature}},
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
    # GET /api/signature/summary  — HTMX: signature frequency modal
    # ------------------------------------------------------------------
    @app.route("/api/signature/summary")
    def api_signature_summary():
        from src.querier.kibana_module import get_signature_frequency
        search_params = build_search_params_from_request(request)
        buckets = get_signature_frequency(search_params)
        return render_template("partials/signature_summary.html", buckets=buckets)

    # ------------------------------------------------------------------
    # GET /api/city/summary  — HTMX: city picker modal
    # ------------------------------------------------------------------
    @app.route("/api/city/summary")
    def api_city_summary():
        from src.querier.kibana_module import get_cities_data
        search_params = build_search_params_from_request(request)
        buckets = get_cities_data(search_params.get("time_range", "now-7d"))
        current_cities = [
            c.strip()
            for c in search_params.get("cities", "").split(",")
            if c.strip() and c.strip().lower() != "all"
        ]
        return render_template(
            "partials/city_summary.html",
            buckets=buckets,
            current_cities=current_cities,
        )

    # ------------------------------------------------------------------
    # GET /api/mantis/search  — HTMX: search Mantis tickets, return card partial
    # ------------------------------------------------------------------
    @app.route("/api/mantis/search")
    def api_mantis_search():
        from src.mantis.mantis_search import search
        query = request.args.get("query", "").strip()
        idx = request.args.get("idx", "0")
        cities_val = request.args.get("cities", "all")
        # Map single city to project filter; multi-city or 'all' → None
        cities = [c.strip() for c in cities_val.split(",") if c.strip() and c.strip().lower() != "all"]
        city = cities[0] if len(cities) == 1 else None
        tickets = search(query, city=city) if query else []
        return render_template("partials/mantis_results.html",
                               tickets=tickets, query=query, idx=idx)

    # ------------------------------------------------------------------
    # POST /api/enrich/<ip>  — HTMX: enrichment card
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
            "greynoise":  greynoise.URL.format(ip=ip),
            "abuseipdb":  abuseipdb.URL.format(ip=ip),
            "shodan":     shodan.URL.format(ip=ip),
            "virustotal": virustotal.URL.format(ip=ip),
        }
        return render_template("partials/enrich_card.html", ip=ip, result=result, urls=urls)

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

    return app
