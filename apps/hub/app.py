"""Flask application factory for the PISCES Hub portal."""

import json
import os
import subprocess
import time

from flask import Flask, render_template


def _read_version() -> str:
    """Read version from pyproject.toml without requiring package installation."""
    toml = os.path.join(os.path.dirname(__file__), "..", "..", "pyproject.toml")
    try:
        with open(toml) as f:
            for line in f:
                if line.startswith("version"):
                    return line.split('"')[1]
    except OSError:
        pass
    return "unknown"


def _git_update_info() -> dict:
    """Fetch origin and return commits-behind count for the current branch.

    Only compares HEAD against origin/<current_branch> so the count is
    always meaningful. Runs once at startup.
    """
    repo = os.path.join(os.path.dirname(__file__), "..", "..")
    info: dict = {"branch": "unknown", "behind": None}
    try:
        subprocess.run(
            ["git", "fetch", "origin"],
            cwd=repo,
            capture_output=True,
            timeout=10,
        )
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo,
            text=True,
            timeout=5,
        ).strip()
        info["branch"] = branch
        result = subprocess.check_output(
            ["git", "rev-list", f"HEAD..origin/{branch}", "--count"],
            cwd=repo,
            text=True,
            timeout=5,
        ).strip()
        info["behind"] = int(result)
    except (subprocess.SubprocessError, OSError, ValueError):
        pass
    return info


_VERSION = _read_version()
_GIT_INFO = _git_update_info()

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
        return render_template("index.html", stats=_gather_stats(), version=_VERSION, git=_GIT_INFO)

    return app
