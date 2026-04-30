"""Flask application factory for PISCES Dashboard."""

import json

from flask import Flask, render_template, request

from apps.dashboard_web import cache as dcache


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    @app.template_filter("intcomma")
    def intcomma(value):
        try:
            return "{:,}".format(int(value))
        except (TypeError, ValueError):
            return value

    @app.context_processor
    def inject_globals():
        return {
            "script_name": request.environ.get("SCRIPT_NAME", ""),
        }

    @app.route("/")
    def index():
        return render_template("dashboard.html")

    @app.route("/api/cache/stats")
    def api_cache_stats():
        s = dcache.stats()
        return (
            json.dumps({**s, "ttl": dcache.TTL}),
            200,
            {"Content-Type": "application/json"},
        )

    @app.route("/api/cache/clear", methods=["GET", "POST"])
    def api_cache_clear():
        dcache.invalidate()
        return "", 204

    @app.route("/api/dashboard/sensors")
    def api_sensor_summary():
        """Sensor browser modal content — terms agg on host.name."""
        from apps.dashboard_web.opensearch.aggregations import agg_opensearch_sensors

        time_range = request.args.get("time_range", "now-24h")
        data = agg_opensearch_sensors(time_range)
        # Build bucket-like dicts matching the sensor_summary.html template
        buckets = [
            {"key": label, "doc_count": count}
            for label, count in zip(data["labels"], data["counts"])
        ]
        current = [
            s.strip()
            for s in request.args.get("sensor", "").split(",")
            if s.strip() and s.strip().lower() != "all"
        ]
        return render_template("sensor_summary.html", buckets=buckets, current_sensors=current)

    from apps.dashboard_web.mantis import bp as mantis_bp
    from apps.dashboard_web.opensearch import bp as opensearch_bp
    from apps.dashboard_web.overview import bp as overview_bp
    from apps.dashboard_web.tickets import bp as tickets_bp

    for bp in [overview_bp, opensearch_bp, mantis_bp, tickets_bp]:
        app.register_blueprint(bp)

    from apps.shared.blueprints import make_shared_static_blueprint

    app.register_blueprint(make_shared_static_blueprint())

    return app
