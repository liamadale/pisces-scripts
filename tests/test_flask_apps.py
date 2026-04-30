"""Smoke tests for Flask application factories.

These tests verify that each app can be created and that basic routes respond
correctly, without requiring a running OpenSearch or Mantis backend.

Data-dependent apps (threat_model, opensearch_web, dashboard_web) have their
data loading mocked so the tests remain fast and offline.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ---------------------------------------------------------------------------
# Hub app — no external dependencies
# ---------------------------------------------------------------------------


def test_hub_create_app_returns_flask() -> None:
    from flask import Flask

    from apps.hub.app import create_app

    app = create_app()
    assert isinstance(app, Flask)


def test_hub_index_returns_200() -> None:
    from apps.hub.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        resp = client.get("/")
    assert resp.status_code == 200


def test_hub_index_contains_app_links() -> None:
    from apps.hub.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as client:
        resp = client.get("/")
    html = resp.data.decode()
    # Hub should link to the other apps
    assert "OpenSearch" in html or "opensearch" in html.lower()
    assert "Mantis" in html or "threat" in html.lower()


# ---------------------------------------------------------------------------
# OpenSearch web app — mock out the query backend
# ---------------------------------------------------------------------------


def _mock_opensearch_data_modules():
    """Return a context manager that stubs out OS network calls."""
    return patch(
        "apps.opensearch_web.queries.cached_run_query",
        return_value=[],
    )


def test_opensearch_create_app_returns_flask() -> None:
    from flask import Flask

    from apps.opensearch_web.app import create_app

    app = create_app()
    assert isinstance(app, Flask)


def test_opensearch_overview_route_exists() -> None:
    from apps.opensearch_web.app import create_app

    app = create_app()
    app.config["TESTING"] = True
    # Map of route URLs — just verify the route is registered, not the response
    rules = {rule.rule for rule in app.url_map.iter_rules()}
    assert "/" in rules


# ---------------------------------------------------------------------------
# Mantis web app — mock out data loading
# ---------------------------------------------------------------------------


def _make_mock_data() -> MagicMock:
    """Build a MagicMock that satisfies all apps.threat_model.data imports."""
    m = MagicMock()
    m.MALICIOUS_ROWS = []
    m.FP_ROWS = []
    m.INFRA_ROWS = []
    m.DNS_RESOLVER_ROWS = []
    m.UNDETERMINED_ROWS = []
    m.ALL_ATTACK_TYPES = []
    m.ALL_BLOCKLISTS = []
    m.ALL_FP_CATEGORIES = []
    m.ALL_INFRA_CATEGORIES = []
    m.TICKETS_BY_ID = {}
    m.MALICIOUS_BY_IP = {}
    m.FP_BY_IP = {}
    m.classify_ip = MagicMock(return_value="unknown")
    m.fmt_attack = MagicMock(side_effect=lambda s: s.replace("_", " ").title())
    m.get_tickets_for_ip = MagicMock(return_value=[])
    m._fp_row = MagicMock(return_value={})
    m._malicious_row = MagicMock(return_value={})
    return m


def test_threat_model_create_app_returns_flask() -> None:
    from flask import Flask

    mock_data = _make_mock_data()
    with patch.dict(sys.modules, {"apps.threat_model.data": mock_data}):
        # Re-import to pick up the mock
        if "apps.threat_model.app" in sys.modules:
            del sys.modules["apps.threat_model.app"]
        from apps.threat_model.app import create_app

        app = create_app()
    assert isinstance(app, Flask)


def test_threat_model_routes_registered() -> None:
    mock_data = _make_mock_data()
    with patch.dict(sys.modules, {"apps.threat_model.data": mock_data}):
        if "apps.threat_model.app" in sys.modules:
            del sys.modules["apps.threat_model.app"]
        from apps.threat_model.app import create_app

        app = create_app()
    rules = {rule.rule for rule in app.url_map.iter_rules()}
    # Should have at least root route
    assert "/" in rules
