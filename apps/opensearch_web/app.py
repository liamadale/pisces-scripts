"""Flask application factory and route definitions for PISCES Web UI."""

import os
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, render_template, request

from apps.opensearch_web import cache as wcache
from apps.opensearch_web.queries import (
    build_search_params_from_request,
    cached_run_query,
    run_cross_protocol_query,
)
from apps.shared.blueprints import (
    make_cache_blueprint,
    make_enrich_blueprint,
    make_mantis_blueprint,
)
from apps.shared.jinja_globals import register_shared_helpers
from src.querier.zeek_modules import (
    CATEGORY_LABELS,
    CATEGORY_ORDER,
    MODULES,
    MODULES_BY_CATEGORY,
)
from src.querier.zeek_modules.base import TIME_RANGES
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
        rows = run_cross_protocol_query(search_params)
        # Build per-category module lists, excluding non-IP modules (pe, capture_loss)
        ip_modules_by_category = {
            cat: [lt for lt in lts if MODULES[lt].SUPPORTS_IP_FILTER]
            for cat, lts in MODULES_BY_CATEGORY.items()
        }
        return render_template(
            "overview.html",
            rows=rows,
            search_params=search_params,
            ip_modules_by_category=ip_modules_by_category,
        )

    # ------------------------------------------------------------------
    # GET /ip/<ip>  — all-protocol view for one IP
    # ------------------------------------------------------------------
    @app.route("/ip/<ip>")
    def ip_pivot(ip: str):
        search_params = build_search_params_from_request(request)
        search_params["src_ip"] = ip

        results: dict = {}
        for lt, mod in MODULES.items():
            if not mod.SUPPORTS_IP_FILTER:
                continue  # pe, capture_loss have no src_ip to pivot on
            sp = dict(search_params)
            results[lt] = cached_run_query(lt, sp)

        return render_template(
            "ip_pivot.html",
            ip=ip,
            results=results,
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
        records = [] if summary_mode else cached_run_query(log_type, search_params)

        return render_template(
            "log_view.html",
            log_type=log_type,
            records=records,
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
        records = cached_run_query(log_type, search_params)
        return render_template(
            "partials/log_rows.html",
            log_type=log_type,
            records=records,
            detail_fields=mod.DETAIL_FIELDS,
            web_columns=mod.WEB_COLUMNS,
        )

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
        )
        body["size"] = 0
        body.pop("sort", None)
        body.pop("_source", None)

        if mod.SUMMARY_TYPE == "grouped":
            # Prefix-grouped aggregation: extract prefix from rule.name,
            # with nested severity breakdown and top rules per group.
            body["aggs"] = {
                "prefixes": {
                    "terms": {
                        "script": {
                            "source": (
                                "def n = doc['rule.name'].value;"
                                "int i = n.indexOf(' ');"
                                "if (i < 0) return n;"
                                "int j = n.indexOf(' ', i + 1);"
                                "if (j < 0) return n.substring(0, i);"
                                "return n.substring(0, j);"
                            ),
                            "lang": "painless",
                        },
                        "size": 50,
                        "order": {"_count": "desc"},
                    },
                    "aggs": {
                        "by_severity": {
                            "terms": {
                                "field": "suricata.alert.severity",
                                "size": 5,
                            }
                        },
                        "top_rules": {
                            "terms": {
                                "field": "rule.name",
                                "size": 10,
                                "order": {"_count": "desc"},
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

        is_inline = request.args.get("inline") == "1"

        if mod.SUMMARY_TYPE == "grouped":
            groups = []
            if raw:
                for b in raw.get("aggregations", {}).get("prefixes", {}).get("buckets", []):
                    sev_map = {
                        s["key"]: s["doc_count"]
                        for s in b.get("by_severity", {}).get("buckets", [])
                    }
                    min_sev = min(sev_map.keys()) if sev_map else 3
                    groups.append(
                        {
                            "prefix": b["key"],
                            "count": b["doc_count"],
                            "min_severity": min_sev,
                            "sev": sev_map,
                            "top_rules": [
                                {"name": r["key"], "count": r["doc_count"]}
                                for r in b.get("top_rules", {}).get("buckets", [])
                            ],
                        }
                    )
            template = (
                "partials/summary_grouped.html" if is_inline else "partials/summary_grouped.html"
            )
            return render_template(
                template,
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
    # POST /api/profile/<ip>  — HTMX: device profile card for private IPs
    # ------------------------------------------------------------------
    @app.route("/api/profile/<ip>", methods=["POST"])
    def api_profile(ip: str):
        from src.querier.zeek_modules.base import is_private

        if not is_private(ip):
            return '<p class="empty-note">Device profiling is for private IPs only.</p>'

        from src.profiler.device_profiler import profile_device

        sensor = request.args.get("sensor", "all")
        time_range = request.args.get("time_range", "now-7d")
        compact = request.args.get("compact") == "1"

        profile = profile_device(ip, time_range=time_range, sensor=sensor)
        return render_template("partials/device_card.html", profile=profile, compact=compact)

    return app
