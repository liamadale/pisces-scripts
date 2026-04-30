"""Flask application factory for the PISCES Hub portal."""

import json
import os
import time

from flask import Flask, render_template

_DATA = os.path.join(os.path.dirname(__file__), "..", "..", "data", "tickets")
_INDEX = os.path.join(_DATA, "indexed", "tickets_index.json")
_ENRICHED = os.path.join(_DATA, "enriched")

_ENRICHED_FILES = {
    "malicious": "malicious_ips.json",
    "false_positive": "false_positive_ips.json",
    "infrastructure": "known_infra_ips.json",
    "undetermined": "undetermined_ips.json",
}


def _count_json(path: str) -> int:
    """Return len() of a JSON array file, or 0 if missing."""
    try:
        with open(path) as f:
            return len(json.load(f))
    except (OSError, json.JSONDecodeError):
        return 0


def _age_str(path: str) -> str:
    """Return human-readable age of a file, e.g. '2h ago' or 'N/A'."""
    try:
        delta = time.time() - os.path.getmtime(path)
    except OSError:
        return "N/A"
    if delta < 60:
        return "just now"
    if delta < 3600:
        return f"{int(delta // 60)}m ago"
    if delta < 86400:
        return f"{int(delta // 3600)}h ago"
    return f"{int(delta // 86400)}d ago"


def _gather_stats() -> dict:
    """Read local data files for hub stats. No API calls."""
    counts = {k: _count_json(os.path.join(_ENRICHED, v)) for k, v in _ENRICHED_FILES.items()}
    counts["tickets"] = _count_json(_INDEX)
    return {
        "counts": counts,
        "index_age": _age_str(_INDEX),
        "model_age": _age_str(os.path.join(_ENRICHED, "malicious_ips.json")),
    }


def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")

    @app.route("/")
    def index():
        return render_template("index.html", stats=_gather_stats())

    return app
