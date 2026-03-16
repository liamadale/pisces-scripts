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
        return json.dumps({**s, "ttl": dcache.TTL}), 200, {"Content-Type": "application/json"}

    @app.route("/api/cache/clear", methods=["GET", "POST"])
    def api_cache_clear():
        dcache.invalidate()
        return "", 204

    from apps.dashboard_web.overview import bp as overview_bp
    from apps.dashboard_web.opensearch import bp as opensearch_bp
    from apps.dashboard_web.kibana import bp as kibana_bp
    from apps.dashboard_web.mantis import bp as mantis_bp

    for bp in [overview_bp, opensearch_bp, kibana_bp, mantis_bp]:
        app.register_blueprint(bp)

    return app
