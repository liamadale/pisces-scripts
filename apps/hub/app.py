"""Flask application factory for the PISCES Hub portal."""

from flask import Flask, render_template


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    @app.route("/")
    def index():
        return render_template("index.html")

    return app
