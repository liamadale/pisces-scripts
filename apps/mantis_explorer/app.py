"""Flask application factory and routes for Mantis Explorer."""

from flask import Flask, abort, render_template, request

from apps.mantis_explorer.data import (
    SLUG_TO_ORG,
    TICKETS_BY_ID,
    compute_escalation_data,
    compute_global_stats,
    compute_org_report,
    compute_org_rows,
    compute_org_stats,
    compute_timeline_data,
    get_report,
    parse_date_params,
    sort_students,
)


def create_app() -> Flask:
    """Create and configure the Mantis Explorer Flask app."""
    app = Flask(__name__, static_folder="static", template_folder="templates")

    from apps.shared.blueprints import make_shared_static_blueprint

    app.register_blueprint(make_shared_static_blueprint())

    @app.context_processor
    def inject_globals() -> dict:
        return {"script_name": request.environ.get("SCRIPT_NAME", "")}

    # ------------------------------------------------------------------
    # GET /  — Overview page (skeleton; HTMX regions load on trigger)
    # ------------------------------------------------------------------
    @app.route("/")
    def index():
        since = request.args.get("since", "")
        until = request.args.get("until", "")
        return render_template("index.html", since=since, until=until)

    # ------------------------------------------------------------------
    # GET /api/stat-row  — HTMX: global summary chips
    # ------------------------------------------------------------------
    @app.route("/api/stat-row")
    def api_stat_row():
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        stats = compute_global_stats(report)
        return render_template("partials/stat_row.html", stats=stats)

    # ------------------------------------------------------------------
    # GET /api/org-table  — HTMX: institution table tbody
    # ------------------------------------------------------------------
    @app.route("/api/org-table")
    def api_org_table():
        since, until = parse_date_params(request.args)
        q = request.args.get("q", "").strip()
        sort = request.args.get("sort", "tickets")
        order = request.args.get("order", "desc")
        report = get_report(since, until)
        rows = compute_org_rows(report, q=q, sort=sort, order=order)
        return render_template(
            "partials/org_table.html",
            rows=rows,
            sort=sort,
            order=order,
            since=since,
            until=until,
        )

    # ------------------------------------------------------------------
    # GET /api/chart/orgs-bar  — HTMX: horizontal bar chart
    # ------------------------------------------------------------------
    @app.route("/api/chart/orgs-bar")
    def api_chart_orgs_bar():
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        rows = compute_org_rows(report)
        return render_template("partials/chart_orgs_bar.html", rows=rows)

    # ------------------------------------------------------------------
    # GET /api/chart/timeline  — HTMX: global area timeline
    # ------------------------------------------------------------------
    @app.route("/api/chart/timeline")
    def api_chart_timeline():
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        timeline = compute_timeline_data(report)
        return render_template("partials/chart_timeline.html", timeline=timeline)

    # ------------------------------------------------------------------
    # GET /api/chart/escalation  — HTMX: escalation grouped bar
    # ------------------------------------------------------------------
    @app.route("/api/chart/escalation")
    def api_chart_escalation():
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        esc = compute_escalation_data(report)
        return render_template("partials/chart_escalation.html", esc=esc)

    # ------------------------------------------------------------------
    # GET /org/<slug>  — Org detail page
    # ------------------------------------------------------------------
    @app.route("/org/<slug>")
    def org_detail(slug: str):
        org_name = SLUG_TO_ORG.get(slug)
        if not org_name:
            abort(404)
        since = request.args.get("since", "")
        until = request.args.get("until", "")
        return render_template(
            "org.html",
            org_name=org_name,
            slug=slug,
            since=since,
            until=until,
        )

    # ------------------------------------------------------------------
    # GET /api/org/<slug>/stat-row  — HTMX: org summary chips
    # ------------------------------------------------------------------
    @app.route("/api/org/<slug>/stat-row")
    def api_org_stat_row(slug: str):
        org_name = SLUG_TO_ORG.get(slug)
        if not org_name:
            abort(404)
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        org_report = compute_org_report(report, org_name)
        stats = compute_org_stats(org_report)
        return render_template("partials/org_stat_row.html", stats=stats, org_name=org_name)

    # ------------------------------------------------------------------
    # GET /api/org/<slug>/timeline  — HTMX: org submission timeline
    # ------------------------------------------------------------------
    @app.route("/api/org/<slug>/timeline")
    def api_org_timeline(slug: str):
        org_name = SLUG_TO_ORG.get(slug)
        if not org_name:
            abort(404)
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        org_report = compute_org_report(report, org_name)
        timeline = compute_timeline_data(org_report)
        return render_template("partials/org_timeline.html", timeline=timeline, org_name=org_name)

    # ------------------------------------------------------------------
    # GET /api/org/<slug>/students  — HTMX: student table tbody
    # ------------------------------------------------------------------
    @app.route("/api/org/<slug>/students")
    def api_org_students(slug: str):
        org_name = SLUG_TO_ORG.get(slug)
        if not org_name:
            abort(404)
        since, until = parse_date_params(request.args)
        q = request.args.get("q", "").strip()
        sort = request.args.get("sort", "activity")
        order = request.args.get("order", "desc")
        report = get_report(since, until)
        org_report = compute_org_report(report, org_name)
        from src.mantis.activity_report import _format_date_range

        rows = []
        for sid, s in sort_students(org_report, sort=sort, order=order, q=q):
            dates = [ref["created_at"] for ref in s.created_tickets if ref.get("created_at")]
            rows.append(
                {
                    "id": sid,
                    "name": s.name,
                    "tickets_created": s.tickets_created,
                    "escalated_tickets": s.escalated_tickets,
                    "notes_written": s.notes_written,
                    "total_activity": s.total_activity,
                    "date_range": _format_date_range(dates),
                }
            )
        return render_template(
            "partials/student_rows.html",
            rows=rows,
            sort=sort,
            order=order,
            slug=slug,
            since=since,
            until=until,
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
    # GET /api/student/<id>/panel  — HTMX: student detail slide panel
    # ------------------------------------------------------------------
    @app.route("/api/student/<int:student_id>/panel")
    def api_student_panel(student_id: int):
        since, until = parse_date_params(request.args)
        report = get_report(since, until)
        student = report.get(student_id)
        if not student:
            return (
                "<p style='color:var(--on-surface-dim);padding:1rem'>Student not found.</p>",
                404,
            )
        return render_template("partials/student_panel.html", student=student)

    return app
