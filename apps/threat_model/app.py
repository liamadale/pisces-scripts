"""Flask application factory and route definitions for the Threat Modeling app."""

import math

from flask import Flask, render_template, request

from apps.threat_model.data import (
    ALL_ATTACK_TYPES,
    ALL_BLOCKLISTS,
    ALL_FP_CATEGORIES,
    ALL_INFRA_CATEGORIES,
    DATA_AVAILABLE,
    DNS_RESOLVER_ROWS,
    FP_BY_IP,
    FP_ROWS,
    INFRA_ROWS,
    MALICIOUS_BY_IP,
    MALICIOUS_ROWS,
    PROFILES_BY_IP,
    TICKETS_BY_ID,
    UNDETERMINED_ROWS,
    _fp_row,
    _malicious_row,
    classify_ip,
    fmt_attack,
    get_tickets_for_ip,
)

TICKETS_PER_CARD_PAGE = 10
DEFAULT_PAGE_SIZE = 50


# ---------------------------------------------------------------------------
# Filtering / sorting / paging helpers
# ---------------------------------------------------------------------------


def _page_args(args) -> tuple[int, int]:
    """Return (page, per_page) from request args."""
    try:
        page = max(1, int(args.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        per_page = int(args.get("per_page", DEFAULT_PAGE_SIZE))
        if per_page not in (25, 50, 100):
            per_page = DEFAULT_PAGE_SIZE
    except (ValueError, TypeError):
        per_page = DEFAULT_PAGE_SIZE
    return page, per_page


def _sort_rows(rows: list[dict], args) -> list[dict]:
    sort = args.get("sort", "ticket_count")
    order = args.get("order", "desc")
    reverse = order != "asc"

    def key(r):
        v = r.get(sort, "")
        if isinstance(v, (int, float)):
            return v
        return str(v).lower()

    try:
        return sorted(rows, key=key, reverse=reverse)
    except TypeError:
        return rows


def _filter_tp(args) -> list[dict]:
    rows = MALICIOUS_ROWS
    attack = args.get("attack", "").strip()
    blocklist = args.get("blocklist", "").strip()
    q = args.get("q", "").strip().lower()
    min_tickets_str = args.get("min_tickets", "").strip()

    if attack:
        rows = [r for r in rows if attack in r["attack_types"]]
    if blocklist:
        rows = [r for r in rows if blocklist in r["blocklists"]]
    if q:
        rows = [r for r in rows if q in r["ip"].lower() or q in r["attack_str"].lower()]
    if min_tickets_str:
        try:
            min_t = int(min_tickets_str)
            rows = [r for r in rows if r["ticket_count"] >= min_t]
        except (ValueError, TypeError):
            pass
    return rows


def _filter_fp(args) -> list[dict]:
    rows = FP_ROWS
    category = args.get("category", "").strip()
    q = args.get("q", "").strip().lower()
    min_score_str = args.get("min_score", "").strip()

    if category:
        rows = [r for r in rows if r["category_raw"] == category]
    if q:
        rows = [r for r in rows if q in r["ip"].lower()]
    if min_score_str:
        try:
            min_s = float(min_score_str)
            rows = [r for r in rows if r["score"] >= min_s]
        except (ValueError, TypeError):
            pass
    return rows


def _filter_dns_resolver(args) -> list[dict]:
    rows = DNS_RESOLVER_ROWS
    q = args.get("q", "").strip().lower()
    if q:
        rows = [r for r in rows if q in r["ip"] or q in r["provider"].lower()]
    return rows


def _filter_infra(args) -> list[dict]:
    rows = INFRA_ROWS
    category = args.get("category", "").strip()
    q = args.get("q", "").strip().lower()
    if category:
        rows = [r for r in rows if r["org_category"] == category]
    if q:
        rows = [r for r in rows if q in r["ip"].lower() or q in r["org_name"].lower()]
    return rows


def _filter_undetermined(args) -> list[dict]:
    rows = UNDETERMINED_ROWS
    q = args.get("q", "").strip().lower()
    min_score_str = args.get("min_score", "").strip()
    if q:
        rows = [r for r in rows if q in r["ip"].lower() or q in r["signals_str"].lower()]
    if min_score_str:
        try:
            min_s = float(min_score_str)
            rows = [r for r in rows if r["score"] >= min_s]
        except (ValueError, TypeError):
            pass
    return rows


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app() -> Flask:
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates",
    )

    from apps.shared.blueprints import make_shared_static_blueprint

    app.register_blueprint(make_shared_static_blueprint())

    # Jinja2 globals / filters
    app.jinja_env.globals["fmt_attack"] = fmt_attack
    app.jinja_env.globals["classify_ip"] = classify_ip

    @app.context_processor
    def inject_globals():
        return {
            "script_name": request.environ.get("SCRIPT_NAME", ""),
            "tp_total": len(MALICIOUS_ROWS),
            "fp_total": len(FP_ROWS),
            "infra_total": len(INFRA_ROWS),
            "dns_resolver_total": len(DNS_RESOLVER_ROWS),
            "undetermined_total": len(UNDETERMINED_ROWS),
        }

    # ------------------------------------------------------------------
    # GET /  — main page
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        return render_template(
            "index.html",
            all_attack_types=ALL_ATTACK_TYPES,
            all_blocklists=ALL_BLOCKLISTS,
            all_fp_categories=ALL_FP_CATEGORIES,
            all_infra_categories=ALL_INFRA_CATEGORIES,
            tp_total=len(MALICIOUS_ROWS),
            fp_total=len(FP_ROWS),
            infra_total=len(INFRA_ROWS),
            dns_resolver_total=len(DNS_RESOLVER_ROWS),
            undetermined_total=len(UNDETERMINED_ROWS),
            data_available=DATA_AVAILABLE,
        )

    # ------------------------------------------------------------------
    # GET /api/search?q=<ip>  — HTMX: threat card for searched IP
    # ------------------------------------------------------------------
    @app.route("/api/search")
    def api_search():
        ip = request.args.get("q", "").strip()
        if not ip:
            return ""
        tickets = get_tickets_for_ip(ip)
        page, per_page = _page_args(request.args)
        ticket_pages = max(1, math.ceil(len(tickets) / TICKETS_PER_CARD_PAGE))
        ticket_slice = tickets[:TICKETS_PER_CARD_PAGE]
        raw_mal = MALICIOUS_BY_IP.get(ip)
        raw_fp = FP_BY_IP.get(ip)
        verdict = classify_ip(ip)
        return render_template(
            "partials/threat_card.html",
            ip=ip,
            verdict=verdict,
            malicious=_malicious_row(raw_mal) if raw_mal else None,
            fp=_fp_row(raw_fp) if raw_fp else None,
            device_profile=PROFILES_BY_IP.get(ip) if verdict == "infra" else None,
            tickets=ticket_slice,
            ticket_page=1,
            ticket_pages=ticket_pages,
            ticket_total=len(tickets),
        )

    # ------------------------------------------------------------------
    # GET /api/ip/<ip>/card  — HTMX: card triggered by row click
    # ------------------------------------------------------------------
    @app.route("/api/ip/<ip>/card")
    def api_ip_card(ip: str):
        tickets = get_tickets_for_ip(ip)
        ticket_pages = max(1, math.ceil(len(tickets) / TICKETS_PER_CARD_PAGE))
        ticket_slice = tickets[:TICKETS_PER_CARD_PAGE]
        from_table = request.args.get("from_table", "")
        raw_mal = MALICIOUS_BY_IP.get(ip)
        raw_fp = FP_BY_IP.get(ip)
        # When clicking from the FP table, prefer fp verdict over malicious
        if from_table == "fp" and raw_fp:
            verdict = "fp"
        else:
            verdict = classify_ip(ip)
        return render_template(
            "partials/threat_card.html",
            ip=ip,
            verdict=verdict,
            malicious=_malicious_row(raw_mal) if raw_mal and verdict != "fp" else None,
            fp=_fp_row(raw_fp) if raw_fp else None,
            device_profile=PROFILES_BY_IP.get(ip) if verdict == "infra" else None,
            tickets=ticket_slice,
            ticket_page=1,
            ticket_pages=ticket_pages,
            ticket_total=len(tickets),
        )

    # ------------------------------------------------------------------
    # GET /api/ip/<ip>/profile  — HTMX: live device profile for private IPs
    # ------------------------------------------------------------------
    @app.route("/api/ip/<ip>/profile")
    def api_ip_profile(ip: str):
        from dataclasses import asdict

        from src.profiler.device_profiler import profile_device
        from src.querier.zeek_modules.base import is_private

        if not is_private(ip):
            return (
                "<p style='color:var(--on-surface-dim);font-size:0.82rem'>Not a private IP.</p>"
            ), 400

        time_range = request.args.get("time_range", "now-7d")
        sensor = request.args.get("sensor", "all")

        try:
            profile = profile_device(ip, time_range=time_range, sensor=sensor)
            dp = asdict(profile)
            dp["dest_port_distribution"] = {
                str(k): v for k, v in dp["dest_port_distribution"].items()
            }
        except Exception as exc:
            app.logger.warning("device profile failed for %s: %s", ip, exc)
            return (
                "<p style='color:var(--on-surface-dim);font-size:0.82rem'>Profile unavailable.</p>"
            ), 200

        return render_template("partials/device_profile_card.html", device_profile=dp)

    # ------------------------------------------------------------------
    # GET /api/ip/<ip>/tickets?page=N  — HTMX: paginate ticket list
    # ------------------------------------------------------------------
    @app.route("/api/ip/<ip>/tickets")
    def api_ip_tickets(ip: str):
        tickets = get_tickets_for_ip(ip)
        try:
            page = max(1, int(request.args.get("page", 1)))
        except (ValueError, TypeError):
            page = 1
        ticket_pages = max(1, math.ceil(len(tickets) / TICKETS_PER_CARD_PAGE))
        page = min(page, ticket_pages)
        start = (page - 1) * TICKETS_PER_CARD_PAGE
        ticket_slice = tickets[start : start + TICKETS_PER_CARD_PAGE]
        return render_template(
            "partials/ticket_list.html",
            ip=ip,
            tickets=ticket_slice,
            ticket_page=page,
            ticket_pages=ticket_pages,
            ticket_total=len(tickets),
        )

    # ------------------------------------------------------------------
    # GET /api/ticket/<tid>  — HTMX: full ticket detail for slide panel
    # ------------------------------------------------------------------
    @app.route("/api/ticket/<tid>")
    def api_ticket_detail(tid: str):
        t = TICKETS_BY_ID.get(str(tid))
        if not t:
            return (
                "<p style='color:var(--on-surface-dim);padding:1rem'>Ticket not found.</p>",
                404,
            )
        return render_template("partials/ticket_detail.html", t=t)

    # ------------------------------------------------------------------
    # GET /api/tp/rows  — HTMX: TP table body
    # ------------------------------------------------------------------
    @app.route("/api/tp/rows")
    def api_tp_rows():
        filtered = _filter_tp(request.args)
        sorted_rows = _sort_rows(filtered, request.args)
        page, per_page = _page_args(request.args)
        total = len(sorted_rows)
        total_pages = max(1, math.ceil(total / per_page))
        page = min(page, total_pages)
        start = (page - 1) * per_page
        rows = sorted_rows[start : start + per_page]
        return render_template(
            "partials/tp_rows.html",
            rows=rows,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            sort=request.args.get("sort", "ticket_count"),
            order=request.args.get("order", "desc"),
            attack=request.args.get("attack", ""),
            blocklist=request.args.get("blocklist", ""),
            q=request.args.get("q", ""),
            min_tickets=request.args.get("min_tickets", ""),
        )

    # ------------------------------------------------------------------
    # GET /api/fp/rows  — HTMX: FP table body
    # ------------------------------------------------------------------
    @app.route("/api/fp/rows")
    def api_fp_rows():
        filtered = _filter_fp(request.args)
        sorted_rows = _sort_rows(filtered, request.args)
        page, per_page = _page_args(request.args)
        total = len(sorted_rows)
        total_pages = max(1, math.ceil(total / per_page))
        page = min(page, total_pages)
        start = (page - 1) * per_page
        rows = sorted_rows[start : start + per_page]
        return render_template(
            "partials/fp_rows.html",
            rows=rows,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            sort=request.args.get("sort", "score"),
            order=request.args.get("order", "desc"),
            category=request.args.get("category", ""),
            q=request.args.get("q", ""),
            min_score=request.args.get("min_score", ""),
        )

    # ------------------------------------------------------------------
    # GET /api/dns-resolver/rows  — HTMX: DNS resolver table body
    # ------------------------------------------------------------------
    @app.route("/api/dns-resolver/rows")
    def api_dns_resolver_rows():
        filtered = _filter_dns_resolver(request.args)
        sorted_rows = _sort_rows(filtered, request.args)
        page, per_page = _page_args(request.args)
        total = len(sorted_rows)
        total_pages = max(1, math.ceil(total / per_page))
        page = min(page, total_pages)
        start = (page - 1) * per_page
        rows = sorted_rows[start : start + per_page]
        return render_template(
            "partials/dns_resolver_rows.html",
            rows=rows,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            sort=request.args.get("sort", "ticket_count"),
            order=request.args.get("order", "desc"),
            q=request.args.get("q", ""),
        )

    # ------------------------------------------------------------------
    # GET /api/infra/rows  — HTMX: Infrastructure table body
    # ------------------------------------------------------------------
    @app.route("/api/infra/rows")
    def api_infra_rows():
        filtered = _filter_infra(request.args)
        sorted_rows = _sort_rows(filtered, request.args)
        page, per_page = _page_args(request.args)
        total = len(sorted_rows)
        total_pages = max(1, math.ceil(total / per_page))
        page = min(page, total_pages)
        start = (page - 1) * per_page
        rows = sorted_rows[start : start + per_page]
        return render_template(
            "partials/infra_rows.html",
            rows=rows,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            sort=request.args.get("sort", "ticket_count"),
            order=request.args.get("order", "desc"),
            category=request.args.get("category", ""),
            q=request.args.get("q", ""),
        )

    # ------------------------------------------------------------------
    # GET /api/undetermined/rows  — HTMX: Undetermined table body
    # ------------------------------------------------------------------
    @app.route("/api/undetermined/rows")
    def api_undetermined_rows():
        filtered = _filter_undetermined(request.args)
        sorted_rows = _sort_rows(filtered, request.args)
        page, per_page = _page_args(request.args)
        total = len(sorted_rows)
        total_pages = max(1, math.ceil(total / per_page))
        page = min(page, total_pages)
        start = (page - 1) * per_page
        rows = sorted_rows[start : start + per_page]
        return render_template(
            "partials/undetermined_rows.html",
            rows=rows,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            sort=request.args.get("sort", "score"),
            order=request.args.get("order", "desc"),
            q=request.args.get("q", ""),
            min_score=request.args.get("min_score", ""),
        )

    return app
