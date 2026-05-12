"""Flask application factory and route definitions for PISCES Web UI."""

import os
from concurrent.futures import as_completed
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, make_response, render_template, request

from apps.opensearch_web import cache as wcache
from apps.opensearch_web.queries import (
    POOL,
    build_search_params_from_request,
    cached_run_query,
    run_cross_protocol_query,
)
from apps.shared.blueprints import (
    make_cache_blueprint,
    make_enrich_blueprint,
    make_mantis_blueprint,
    make_shared_static_blueprint,
)
from apps.shared.jinja_globals import register_shared_helpers
from src.querier.zeek_modules import (
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    MODULES,
    MODULES_BY_CATEGORY,
)
from src.querier.zeek_modules.base import (
    TIME_RANGES,
    OpenSearchAuthError,
    OpenSearchConnectionError,
)
from src.utils.format import fmt_dur

# ------------------------------------------------------------------
# Timestamp helpers (used by Jinja filters/globals and share URLs)
# ------------------------------------------------------------------

_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def resolve_time_range(time_range: str) -> tuple[str, str]:
    """Convert relative range like ``'now-24h'`` to ``(from_iso, to_iso)``."""
    now = datetime.now(timezone.utc)
    val = int(time_range.replace("now-", "")[:-1])
    unit = time_range[-1]
    from_dt = now - timedelta(**{_UNITS[unit]: val})
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return from_dt.strftime(fmt), now.strftime(fmt)


def fmt_time_window(time_range: str) -> str:
    """``'now-24h'`` → ``'Apr 14 15:43 → Apr 15 15:43 UTC'``."""
    f, t = resolve_time_range(time_range)
    fmt = "%b %d %H:%M"
    return (
        f"{datetime.fromisoformat(f).strftime(fmt)} → {datetime.fromisoformat(t).strftime(fmt)} UTC"
    )


def fmt_ts(iso_str: str, full: bool = False) -> str:
    """Jinja filter: format an ISO timestamp for display."""
    if not iso_str:
        return "—"
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S") if full else dt.strftime("%b %d %H:%M")
    except (ValueError, TypeError):
        return iso_str[:16] if iso_str else "—"


def _resolve_city(request):  # type: ignore[no-untyped-def]
    from src.mantis.mantis_search import sensor_to_project

    return sensor_to_project(request.args.get("sensor", "all"))


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    register_shared_helpers(app)

    # opensearch-specific filters / globals
    app.jinja_env.filters["fmt_dur"] = fmt_dur
    app.jinja_env.filters["fmt_ts"] = fmt_ts
    app.jinja_env.globals["fmt_time_window"] = fmt_time_window

    # Register shared blueprints
    app.register_blueprint(make_shared_static_blueprint())
    app.register_blueprint(make_enrich_blueprint())
    app.register_blueprint(make_mantis_blueprint(_resolve_city))
    app.register_blueprint(make_cache_blueprint(wcache))

    # Compute CSS version once at startup from file mtime — busts browser cache on deploy
    _css_path = os.path.join(app.static_folder, "pisces.css")
    _css_version = str(int(os.path.getmtime(_css_path))) if os.path.exists(_css_path) else "1"

    # Make TIME_RANGES, MODULES, and nav data available to all templates
    @app.context_processor
    def inject_globals() -> dict:
        return {
            "TIME_RANGES": TIME_RANGES,
            "MODULES": MODULES,
            "script_name": request.environ.get("SCRIPT_NAME", ""),
            "css_version": _css_version,
        }

    @app.context_processor
    def inject_nav_data() -> dict:
        return {
            "proto_icons": {lt: mod.WEB_ICON for lt, mod in MODULES.items()},
            "category_icons": {
                "alerts": "fa-fire",
                "network": "fa-sitemap",
                "web": "fa-cloud",
                "remote": "fa-right-to-bracket",
                "auth": "fa-fingerprint",
                "messaging": "fa-comments",
                "files": "fa-folder",
                "ot": "fa-industry",
            },
            "category_order": CATEGORY_ORDER,
            "category_labels": CATEGORY_LABELS,
            "modules_by_category": MODULES_BY_CATEGORY,
        }

    # ------------------------------------------------------------------
    # GET /  — cross-protocol IP matrix
    # ------------------------------------------------------------------
    @app.route("/")
    def overview():
        search_params = build_search_params_from_request(request)
        error = None
        rows = []
        try:
            rows = run_cross_protocol_query(search_params)
        except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
            error = str(exc)
        # Build per-category module lists, excluding non-IP modules (pe, capture_loss)
        ip_modules_by_category = {
            cat: [lt for lt in lts if MODULES[lt].SUPPORTS_IP_FILTER]
            for cat, lts in MODULES_BY_CATEGORY.items()
        }
        return render_template(
            "overview.html",
            rows=rows,
            error=error,
            search_params=search_params,
            ip_modules_by_category=ip_modules_by_category,
        )

    # ------------------------------------------------------------------
    # GET /ip/<ip>  — all-protocol view for one IP
    # ------------------------------------------------------------------
    @app.route("/ip/<ip>")
    def ip_pivot(ip: str):
        from urllib.parse import urlencode

        ip_role = request.args.get("ip_role", "both")
        if ip_role not in ("src", "dest", "both"):
            ip_role = "both"

        search_params = build_search_params_from_request(request)
        if ip_role == "dest":
            search_params["dest_ip"] = ip
            search_params["src_ip"] = None
        elif ip_role == "src":
            search_params["src_ip"] = ip
            search_params["dest_ip"] = None
        else:  # both
            search_params["any_ip"] = ip
            search_params["src_ip"] = None
            search_params["dest_ip"] = None

        # Build toggle URLs preserving all other query params
        base_args = {k: v for k, v in request.args.items() if k != "ip_role"}
        script_name = request.environ.get("SCRIPT_NAME", "")
        src_url = f"{script_name}/ip/{ip}?ip_role=src&{urlencode(base_args)}"
        dest_url = f"{script_name}/ip/{ip}?ip_role=dest&{urlencode(base_args)}"
        both_url = f"{script_name}/ip/{ip}?ip_role=both&{urlencode(base_args)}"

        ip_modules = [lt for lt, mod in MODULES.items() if mod.SUPPORTS_IP_FILTER]
        results: dict = {}
        error = None
        first_error: Exception | None = None
        futures = {POOL.submit(cached_run_query, lt, dict(search_params)): lt for lt in ip_modules}
        for f in as_completed(futures):
            lt = futures[f]
            try:
                results[lt] = f.result()
            except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
                if first_error is None:
                    first_error = exc
                results[lt] = []
            except Exception:
                app.logger.exception("ip_pivot query failed for %s", lt)
                results[lt] = []
        if first_error is not None:
            error = str(first_error)

        return render_template(
            "ip_pivot.html",
            ip=ip,
            ip_role=ip_role,
            src_url=src_url,
            dest_url=dest_url,
            both_url=both_url,
            results=results,
            error=error,
            search_params=search_params,
        )

    # ------------------------------------------------------------------
    # GET /log/<log_type>  — single-protocol drill-down
    # ------------------------------------------------------------------
    @app.route("/log/<log_type>")
    def log_view(log_type: str):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = mod.EXTRA_PARAMS
        search_params = build_search_params_from_request(request, extra_keys)

        # Summary-capable modules show aggregation by default; skip raw query
        # unless the user has drilled into a specific value.
        has_drill_filter = bool(mod.SUMMARY_PARAM and search_params.get(mod.SUMMARY_PARAM))
        summary_mode = bool(mod.SUMMARY_FIELD) and not has_drill_filter
        error = None
        records = []
        if not summary_mode:
            try:
                records = cached_run_query(log_type, search_params)
            except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
                error = str(exc)

        return render_template(
            "log_view.html",
            log_type=log_type,
            records=records,
            error=error,
            search_params=search_params,
            extra_keys=extra_keys,
            detail_fields=mod.DETAIL_FIELDS,
            web_columns=mod.WEB_COLUMNS,
            summary_field=mod.SUMMARY_FIELD,
            summary_param=mod.SUMMARY_PARAM,
            summary_mode=summary_mode,
        )

    # ------------------------------------------------------------------
    # POST /api/search/<log_type>  — HTMX: re-run query, return table rows partial
    # ------------------------------------------------------------------
    @app.route("/api/search/<log_type>", methods=["POST"])
    def api_search(log_type: str):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = mod.EXTRA_PARAMS
        search_params = build_search_params_from_request(request, extra_keys)

        etag = f'"{wcache.raw_key(log_type, search_params)}"'
        if (
            request.headers.get("If-None-Match") == etag
            and wcache.get(log_type, search_params) is not None
        ):
            return "", 304

        try:
            records = cached_run_query(log_type, search_params)
        except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
            return render_template(
                "partials/log_rows.html",
                log_type=log_type,
                records=[],
                error=str(exc),
                detail_fields=mod.DETAIL_FIELDS,
                web_columns=mod.WEB_COLUMNS,
            )
        resp = make_response(
            render_template(
                "partials/log_rows.html",
                log_type=log_type,
                records=records,
                error=None,
                detail_fields=mod.DETAIL_FIELDS,
                web_columns=mod.WEB_COLUMNS,
            )
        )
        resp.headers["ETag"] = etag
        return resp

    # ------------------------------------------------------------------
    # GET /api/detail/<log_type>/<int:i>  — HTMX: expanded record detail
    # ------------------------------------------------------------------
    @app.route("/api/detail/<log_type>/<int:i>")
    def api_detail(log_type: str, i: int):
        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        extra_keys = mod.EXTRA_PARAMS
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
            supports_fp=mod.SUPPORTS_FP,
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
            append_clauses_to_file,
            ensure_subcategory,
            filter_file_path,
        )

        category = request.form.get("category", "").strip()
        subcategory = request.form.get("subcategory", "").strip()
        filter_type = request.form.get("filter_type", "")
        src_ip = request.form.get("src_ip", "")
        dest_ip = request.form.get("dest_ip", "")
        notice_note = request.form.get("notice_note", "")
        comment = request.form.get("comment", "").strip()
        idx = request.form.get("idx", "0")

        if not category or not subcategory:
            return render_template(
                "partials/filter_result.html",
                success=False,
                error="Category and subcategory are required.",
                idx=idx,
            )

        if filter_type == "src_ip":
            clause = {"term": {"src_ip": src_ip}}
        elif filter_type == "dest_ip":
            clause = {"term": {"dest_ip": dest_ip}}
        elif filter_type == "notice_src_ip_and_note":
            clause = {
                "bool": {
                    "must": [
                        {"term": {"src_ip": src_ip}},
                        {"term": {"zeek.notice.note": notice_note}},
                    ]
                }
            }
        else:
            return render_template(
                "partials/filter_result.html",
                success=False,
                error=f"Unknown filter type: {filter_type!r}",
                idx=idx,
            )

        if comment:
            clause["comment"] = comment

        try:
            path = filter_file_path(category, subcategory)
            append_clauses_to_file(path, [clause], author="web")
            ensure_subcategory(category, subcategory)
            return render_template(
                "partials/filter_result.html",
                success=True,
                category=category,
                subcategory=subcategory,
                idx=idx,
            )
        except Exception as exc:
            return render_template(
                "partials/filter_result.html", success=False, error=str(exc), idx=idx
            )

    # ------------------------------------------------------------------
    # GET /api/share  — generate PISCES + Dashboards share URLs
    # ------------------------------------------------------------------
    @app.route("/api/share")
    def api_share():
        """Return PISCES and Dashboards URLs for the current view."""
        from flask import jsonify

        from src.utils.share_url import (
            ShareContext,
            build_dashboards_path,
            build_pisces_url,
            shorten_dashboards_url,
        )

        _share_lt = request.args.get("log_type", "")
        _share_extra_keys = MODULES[_share_lt].EXTRA_PARAMS if _share_lt in MODULES else []
        search_params = build_search_params_from_request(request, _share_extra_keys)

        # Resolve absolute time range
        time_from = search_params.get("time_from") or ""
        time_to = search_params.get("time_to") or ""
        if not (time_from and time_to):
            time_from, time_to = resolve_time_range(search_params.get("time_range", "now-24h"))

        page_type = request.args.get("page_type", "overview")
        log_type = request.args.get("log_type") or None

        # Collect protocol-specific extra params
        extra: dict[str, str] = {}
        if log_type:
            for key in MODULES[log_type].EXTRA_PARAMS if log_type in MODULES else []:
                val = search_params.get(key)
                if val:
                    extra[key] = str(val)

        ctx = ShareContext(
            src_ip=search_params.get("src_ip"),
            sensor=search_params.get("sensor", "all"),
            time_from=time_from,
            time_to=time_to,
            log_type=log_type,
            page_type=page_type,
            extra_params=extra,
        )

        pisces_url = build_pisces_url(ctx, script_name=request.script_root)
        discover_path = build_dashboards_path(ctx)

        dashboards_base = os.environ.get("OPENSEARCH_URL", "")
        short_url = None
        if dashboards_base:
            username = os.environ.get("PISCES_USERNAME", "")
            password = os.environ.get("PISCES_PASSWORD", "")
            if username and password:
                short_url = shorten_dashboards_url(
                    discover_path, dashboards_base, (username, password)
                )

        long_url = (dashboards_base + discover_path) if dashboards_base else ""

        return jsonify(
            {
                "pisces": pisces_url,
                "dashboards": short_url or long_url,
                "dashboards_long": long_url,
            }
        )

    # ------------------------------------------------------------------
    # GET /api/summary/<log_type>  — HTMX: field-frequency aggregation browse modal
    # ------------------------------------------------------------------
    @app.route("/api/summary/<log_type>")
    def api_summary(log_type: str):
        from src.querier.zeek_modules.base import (
            FILTERS_DIR,
            build_base_query,
            load_with_remap,
            query_opensearch,
        )

        if log_type not in MODULES:
            abort(404)
        mod = MODULES[log_type]
        if not mod.SUMMARY_FIELD:
            abort(404)

        search_params = build_search_params_from_request(request)
        must_not, _, _ = load_with_remap(FILTERS_DIR)
        sensor_val = search_params.get("sensor", "all")
        sensors = (
            [s.strip() for s in str(sensor_val).split(",")]
            if sensor_val and str(sensor_val).lower() != "all"
            else None
        )

        extra_must, _ = mod.build_extra_must({})
        body, params = build_base_query(
            must_not=must_not,
            extra_must=extra_must,
            source_fields=mod.SOURCE_FIELDS,
            limit=0,
            time_range=search_params.get("time_range", "now-24h"),
            sensors=sensors,
            datasets=mod.DATASETS,
            public_only=search_params.get("public_only", False),
            src_ip_filter=search_params.get("src_ip"),
            direction=search_params.get("direction"),
            time_from=search_params.get("time_from"),
            time_to=search_params.get("time_to"),
            sort=False,
        )
        body["size"] = 0
        body.pop("_source", None)

        if mod.SUMMARY_TYPE == "grouped":
            # Aggregate on the full rule.name field; Python groups into prefixes.
            # Replaces a painless script that ran on every document server-side.
            body["aggs"] = {
                "rules": {
                    "terms": {
                        "field": mod.SUMMARY_FIELD,
                        "size": 500,
                        "order": {"_count": "desc"},
                    },
                    "aggs": {
                        "by_severity": {
                            "terms": {
                                "field": "suricata.alert.severity",
                                "size": 5,
                            }
                        },
                    },
                }
            }
        else:
            body["aggs"] = {
                "items": {
                    "terms": {
                        "field": mod.SUMMARY_FIELD,
                        "size": 500,
                        "order": {"_count": "asc"},
                    }
                }
            }

        raw = query_opensearch(body, params)

        if mod.SUMMARY_TYPE == "grouped":
            # Group the flat rule.name buckets into two-word prefixes in Python.
            groups_by_prefix: dict[str, dict] = {}
            if raw:
                for b in raw.get("aggregations", {}).get("rules", {}).get("buckets", []):
                    rule_name: str = b["key"]
                    count: int = b["doc_count"]
                    sev_map = {
                        s["key"]: s["doc_count"]
                        for s in b.get("by_severity", {}).get("buckets", [])
                    }
                    # Mirror the painless prefix logic: up to the second space
                    i = rule_name.find(" ")
                    if i < 0:
                        prefix = rule_name
                    else:
                        j = rule_name.find(" ", i + 1)
                        prefix = rule_name[:i] if j < 0 else rule_name[:j]

                    if prefix not in groups_by_prefix:
                        groups_by_prefix[prefix] = {
                            "prefix": prefix,
                            "count": 0,
                            "sev": {},
                            "top_rules": [],
                        }
                    g = groups_by_prefix[prefix]
                    g["count"] += count
                    for sev, cnt in sev_map.items():
                        g["sev"][sev] = g["sev"].get(sev, 0) + cnt
                    g["top_rules"].append({"name": rule_name, "count": count})

            groups = sorted(groups_by_prefix.values(), key=lambda g: -g["count"])[:50]
            for g in groups:
                g["top_rules"] = sorted(g["top_rules"], key=lambda r: -r["count"])[:10]
                g["min_severity"] = min(g["sev"].keys()) if g["sev"] else 3

            return render_template(
                "partials/summary_grouped.html",
                groups=groups,
                summary_param=mod.SUMMARY_PARAM,
            )

        buckets = []
        if raw:
            buckets = raw.get("aggregations", {}).get("items", {}).get("buckets", [])

        template = (
            "partials/summary_inline.html"
            if request.args.get("inline") == "1"
            else "partials/summary_modal.html"
        )
        return render_template(
            template,
            buckets=buckets,
            summary_param=mod.SUMMARY_PARAM,
        )

    # ------------------------------------------------------------------
    # GET /api/sensor/summary  — HTMX: sensor activity aggregation
    # ------------------------------------------------------------------
    @app.route("/api/sensor/summary")
    def api_sensor_summary():
        from src.querier.zeek_modules.base import (
            build_base_query,
            query_opensearch,
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
            time_from=search_params.get("time_from"),
            time_to=search_params.get("time_to"),
            sort=False,
        )
        body["size"] = 0
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
    # POST /api/profile/<ip>  — HTMX: device profile card for private IPs
    # ------------------------------------------------------------------
    @app.route("/api/profile/<ip>", methods=["POST"])
    def api_profile(ip: str):
        from src.querier.zeek_modules.base import is_private

        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-7d")
        compact = request.args.get("compact") == "1"

        try:
            if is_private(ip):
                from src.profiler.device_profiler import profile_device

                profile = profile_device(ip, time_range=time_range, sensor=sensor)
                return render_template(
                    "partials/device_card.html", profile=profile, compact=compact
                )
            else:
                from src.profiler.public_ip_profiler import profile_public_ip

                profile = profile_public_ip(ip, time_range=time_range)
                return render_template(
                    "partials/public_device_card.html", profile=profile, compact=compact
                )
        except (OpenSearchConnectionError, OpenSearchAuthError) as exc:
            return (
                f'<p class="investigate-error">'
                f'<i class="fa-solid fa-triangle-exclamation"></i> {exc}</p>'
            )

    # ------------------------------------------------------------------
    # GET /investigate/<src_ip>/<dest_ip>  — one-click incident context page
    # ------------------------------------------------------------------
    @app.route("/investigate/<src_ip>/<dest_ip>")
    def investigate_view(src_ip: str, dest_ip: str):
        search_params = build_search_params_from_request(request)
        return render_template(
            "investigate.html",
            src_ip=src_ip,
            dest_ip=dest_ip,
            search_params=search_params,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/profiles  — HTMX: device profiles for src + dest
    # ------------------------------------------------------------------
    @app.route("/api/investigate/profiles")
    def api_investigate_profiles():
        from src.enricher.threat_intel import enrich_ip
        from src.profiler.device_profiler import profile_device
        from src.profiler.public_ip_profiler import profile_public_ip
        from src.querier.zeek_modules.base import is_private

        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        src_profile = None
        dest_profile = None
        src_enrichment = None
        dest_enrichment = None
        src_error = None
        dest_error = None

        def _do_src():
            nonlocal src_profile, src_enrichment, src_error
            try:
                if is_private(src_ip):
                    src_profile = profile_device(src_ip, time_range=time_range, sensor=sensor)
                else:
                    src_profile = profile_public_ip(src_ip, time_range=time_range)
                    src_enrichment = enrich_ip(src_ip, offer_fp=False)
            except Exception as exc:
                app.logger.exception("api_investigate_profiles src failed")
                src_error = str(exc)

        def _do_dest():
            nonlocal dest_profile, dest_enrichment, dest_error
            try:
                if is_private(dest_ip):
                    dest_profile = profile_device(dest_ip, time_range=time_range, sensor=sensor)
                else:
                    dest_profile = profile_public_ip(dest_ip, time_range=time_range)
                    dest_enrichment = enrich_ip(dest_ip, offer_fp=False)
            except Exception as exc:
                app.logger.exception("api_investigate_profiles dest failed")
                dest_error = str(exc)

        f_src = POOL.submit(_do_src)
        f_dest = POOL.submit(_do_dest)
        f_src.result()
        f_dest.result()

        def _enrich_urls(ip: str) -> dict:
            from src.enricher import abuseipdb, greynoise, shodan, virustotal

            return {
                "greynoise": greynoise.URL.format(ip=ip),
                "abuseipdb": abuseipdb.URL.format(ip=ip),
                "shodan": shodan.URL.format(ip=ip),
                "virustotal": virustotal.URL.format(ip=ip),
            }

        return render_template(
            "partials/investigate_profiles.html",
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_profile=src_profile,
            dest_profile=dest_profile,
            src_enrichment=src_enrichment,
            dest_enrichment=dest_enrichment,
            src_urls=_enrich_urls(src_ip) if src_enrichment else None,
            dest_urls=_enrich_urls(dest_ip) if dest_enrichment else None,
            src_error=src_error,
            dest_error=dest_error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/auth  — HTMX: Kerberos + NTLM auth history
    # ------------------------------------------------------------------
    @app.route("/api/investigate/auth")
    def api_investigate_auth():
        from src.correlator.incident_context import query_auth_history

        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        try:
            kerberos, ntlm = query_auth_history(src_ip, dest_ip, sensor, time_range)
            error = None
        except Exception as exc:
            app.logger.exception("api_investigate_auth failed")
            kerberos, ntlm, error = [], [], str(exc)

        return render_template(
            "partials/investigate_auth.html",
            kerberos_history=kerberos,
            ntlm_history=ntlm,
            src_ip=src_ip,
            dest_ip=dest_ip,
            error=error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/chain  — HTMX: ATTACK::* notice chain for src_ip
    # ------------------------------------------------------------------
    @app.route("/api/investigate/chain")
    def api_investigate_chain():
        from src.correlator.incident_context import query_attack_chain

        src_ip = request.args.get("src_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        try:
            chain = query_attack_chain(src_ip, sensor, time_range)
            error = None
        except Exception as exc:
            app.logger.exception("api_investigate_chain failed")
            chain, error = [], str(exc)

        return render_template(
            "partials/investigate_chain.html",
            attack_chain=chain,
            src_ip=src_ip,
            error=error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/notices  — HTMX: Zeek notices for IP pair
    # ------------------------------------------------------------------
    @app.route("/api/investigate/notices")
    def api_investigate_notices():
        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        try:
            from src.querier.zeek_modules.base import run_query

            base = {
                "sensor": sensor,
                "time_range": time_range,
                "limit": 200,
                "no_filters": False,
                "public_only": False,
                "raise_on_error": False,
            }
            fwd = run_query(MODULES["notice"], {**base, "src_ip": src_ip})
            fwd = [r for r in fwd if r.get("dest_ip") == dest_ip]
            rev = run_query(MODULES["notice"], {**base, "src_ip": dest_ip})
            rev = [r for r in rev if r.get("dest_ip") == src_ip]
            records = fwd + rev
            records.sort(key=lambda r: r.get("timestamp", ""))
            error = None
        except Exception as exc:
            app.logger.exception("api_investigate_notices failed")
            records, error = [], str(exc)

        return render_template(
            "partials/investigate_notices.html",
            notices=records,
            src_ip=src_ip,
            dest_ip=dest_ip,
            error=error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/suricata  — HTMX: Suricata alerts for IP pair
    # ------------------------------------------------------------------
    @app.route("/api/investigate/suricata")
    def api_investigate_suricata():
        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        try:
            from src.querier.zeek_modules.base import run_query

            base = {
                "sensor": sensor,
                "time_range": time_range,
                "limit": 200,
                "no_filters": False,
                "public_only": False,
                "raise_on_error": False,
                "exclude_stream": True,
            }
            # src→dest direction
            fwd = run_query(MODULES["suricata_alert"], {**base, "src_ip": src_ip})
            fwd = [r for r in fwd if r.get("dest_ip") == dest_ip]
            # dest→src direction
            rev = run_query(MODULES["suricata_alert"], {**base, "src_ip": dest_ip})
            rev = [r for r in rev if r.get("dest_ip") == src_ip]
            records = fwd + rev
            records.sort(key=lambda r: r.get("timestamp", ""))
            error = None
        except Exception as exc:
            app.logger.exception("api_investigate_suricata failed")
            records, error = [], str(exc)

        return render_template(
            "partials/investigate_suricata.html",
            alerts=records,
            src_ip=src_ip,
            dest_ip=dest_ip,
            error=error,
        )

        return render_template(
            "partials/investigate_suricata.html",
            alerts=records,
            src_ip=src_ip,
            dest_ip=dest_ip,
            error=error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/tickets  — HTMX: Mantis tickets for src + dest
    # ------------------------------------------------------------------
    @app.route("/api/investigate/tickets")
    def api_investigate_tickets():
        from src.mantis.mantis_search import search as search_tickets

        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")

        try:
            src_tickets = search_tickets(src_ip) if src_ip else []
            dest_tickets = search_tickets(dest_ip) if dest_ip else []
            # Deduplicate: drop dest tickets already shown under src
            src_ids = {t.get("id") for t in src_tickets}
            dest_tickets = [t for t in dest_tickets if t.get("id") not in src_ids]
            error = None
        except Exception as exc:
            app.logger.exception("api_investigate_tickets failed")
            src_tickets, dest_tickets, error = [], [], str(exc)

        return render_template(
            "partials/investigate_tickets.html",
            src_ip=src_ip,
            dest_ip=dest_ip,
            src_tickets=src_tickets,
            dest_tickets=dest_tickets,
            error=error,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/timeline  — HTMX: merged chronological event list
    # ------------------------------------------------------------------
    @app.route("/api/investigate/timeline")
    def api_investigate_timeline():
        from src.correlator.incident_context import (
            IncidentContext,
            build_timeline,
            query_attack_chain,
            query_auth_history,
        )

        src_ip = request.args.get("src_ip", "")
        dest_ip = request.args.get("dest_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        kerberos: list[dict] = []
        ntlm: list[dict] = []
        chain: list[dict] = []
        errors: dict[str, str] = {}

        def _auth() -> tuple[list[dict], list[dict]]:
            return query_auth_history(src_ip, dest_ip, sensor, time_range)

        def _chain() -> list[dict]:
            return query_attack_chain(src_ip, sensor, time_range)

        f_auth = POOL.submit(_auth)
        f_chain = POOL.submit(_chain)
        for fut in as_completed([f_auth, f_chain]):
            if fut is f_auth:
                try:
                    kerberos, ntlm = fut.result()
                except Exception as exc:
                    app.logger.exception("api_investigate_timeline auth failed")
                    errors["auth"] = str(exc)
            else:
                try:
                    chain = fut.result()
                except Exception as exc:
                    app.logger.exception("api_investigate_timeline chain failed")
                    errors["chain"] = str(exc)

        ctx = IncidentContext(
            trigger_type="ip_pair",
            trigger={},
            src_ip=src_ip,
            dest_ip=dest_ip,
            sensor=sensor,
            time_range=time_range,
            kerberos_history=kerberos,
            ntlm_history=ntlm,
            attack_chain=chain,
            errors=errors,
        )
        timeline = build_timeline(ctx)

        return render_template(
            "partials/investigate_timeline.html",
            timeline=timeline,
            errors=errors,
        )

    # ------------------------------------------------------------------
    # GET /api/investigate/log_counts  — HTMX: per-module record counts for src_ip
    # ------------------------------------------------------------------
    @app.route("/api/investigate/log_counts")
    def api_investigate_log_counts():
        src_ip = request.args.get("src_ip", "")
        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-24h")

        search_params: dict = {
            "time_range": time_range,
            "time_from": None,
            "time_to": None,
            "sensor": sensor,
            "limit": 500,
            "public_only": False,
            "src_ip": src_ip or None,
            "dest_ip": None,
            "direction": None,
            "no_filters": False,
            "use_cache": False,
        }

        counts: dict[str, int] = {}
        futures = {POOL.submit(cached_run_query, lt, dict(search_params)): lt for lt in MODULES}
        for fut in as_completed(futures):
            lt = futures[fut]
            try:
                counts[lt] = len(fut.result())
            except Exception:
                app.logger.exception("log count query failed for %s", lt)
                counts[lt] = 0

        return render_template(
            "partials/investigate_log_counts.html",
            counts=counts,
            src_ip=src_ip,
            sensor=sensor,
            time_range=time_range,
        )

    return app
