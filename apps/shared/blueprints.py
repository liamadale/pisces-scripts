"""Shared Flask blueprint factories for routes that are identical across web apps."""

import json
import os
from typing import Any, Callable

from flask import Blueprint, render_template, request

from src.querier.zeek_modules.base import is_private

_TEMPLATES = os.path.join(os.path.dirname(__file__), "templates")


def make_enrich_blueprint() -> Blueprint:
    """Blueprint for POST /api/enrich/<ip> — threat intel enrichment card."""
    bp = Blueprint("shared_enrich", __name__, template_folder=_TEMPLATES)

    @bp.route("/api/enrich/<ip>", methods=["POST"])
    def api_enrich(ip: str) -> Any:
        if is_private(ip):
            return (
                '<p class="empty-note">'
                '<i class="fa-solid fa-house-lock"></i> Private IP — enrichment unavailable'
                "</p>"
            )
        from src.enricher import abuseipdb, greynoise, shodan, virustotal
        from src.enricher.threat_intel import enrich_ip

        result = enrich_ip(ip, offer_fp=False)
        urls = {
            "greynoise": greynoise.URL.format(ip=ip),
            "abuseipdb": abuseipdb.URL.format(ip=ip),
            "shodan": shodan.URL.format(ip=ip),
            "virustotal": virustotal.URL.format(ip=ip),
        }
        return render_template("partials/enrich_card.html", ip=ip, result=result, urls=urls)

    return bp


def make_mantis_blueprint(
    resolve_city: Callable[[Any], str | None],
) -> Blueprint:
    """Blueprint for GET /api/mantis/search — Mantis ticket search card.

    Args:
        resolve_city: Callable that accepts a Flask request and returns a city
            string (for project-scoped search) or None (search all projects).
    """
    bp = Blueprint("shared_mantis", __name__, template_folder=_TEMPLATES)

    @bp.route("/api/mantis/search")
    def api_mantis_search() -> Any:
        from src.mantis.mantis_search import search

        query = request.args.get("query", "").strip()
        idx = request.args.get("idx", "0")
        city = resolve_city(request)
        tickets = search(query, city=city) if query else []
        return render_template(
            "partials/mantis_results.html", tickets=tickets, query=query, idx=idx
        )

    return bp


def make_cache_blueprint(cache_module: Any) -> Blueprint:
    """Blueprint for /api/cache/stats and /api/cache/clear debug endpoints."""
    bp = Blueprint("shared_cache", __name__)

    @bp.route("/api/cache/stats")
    def api_cache_stats() -> Any:
        s = cache_module.stats()
        return (
            json.dumps({**s, "ttl": cache_module.TTL}),
            200,
            {"Content-Type": "application/json"},
        )

    @bp.route("/api/cache/clear", methods=["GET", "POST"])
    def api_cache_clear() -> Any:
        cache_module.invalidate()
        return "", 204

    return bp
