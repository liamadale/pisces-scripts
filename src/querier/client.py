#!/usr/bin/env python3
"""OpenSearch connection management: session lifecycle and raw query execution."""

import atexit
import os
import sys

import httpx
from rich.console import Console

console = Console(file=sys.stderr)

OPENSEARCH_URL = os.environ.get("OPENSEARCH_URL", "https://pisces-opensearch.cyberrangepoulsbo.com")
INDEX = "arkime_sessions3-*"

_DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "osd-xsrf": "true",
}


class OpenSearchConnectionError(RuntimeError):
    """Raised when OpenSearch is unreachable or the URL / credentials are not configured."""


class OpenSearchAuthError(RuntimeError):
    """Raised when OpenSearch rejects the supplied credentials (HTTP 401)."""


# ---------------------------------------------------------------------------
# Sync client (CLI + per-request web calls)
# ---------------------------------------------------------------------------

# Module-level client cache: (url, username, password, client).
_client_cache: tuple[str, str, str, httpx.Client] | None = None


def _opensearch_client() -> tuple[str, httpx.Client]:
    """Return (base_url, authenticated httpx.Client).

    The Client is cached at module level and reused as long as credentials
    remain unchanged, so the connection pool stays warm across calls.
    Raises OpenSearchConnectionError when credentials are not configured.
    """
    global _client_cache

    opensearch_url = os.environ.get("OPENSEARCH_URL", OPENSEARCH_URL)
    username = os.environ.get("PISCES_USERNAME", "")
    password = os.environ.get("PISCES_PASSWORD", "")

    if not username or not password:
        raise OpenSearchConnectionError(
            "PISCES_USERNAME and PISCES_PASSWORD must be set — check your .env file"
        )

    if _client_cache is not None:
        cached_url, cached_user, cached_pass, cached_client = _client_cache
        if (cached_url, cached_user, cached_pass) == (opensearch_url, username, password):
            return opensearch_url, cached_client

    client = httpx.Client(
        auth=(username, password),
        verify=False,
        headers=_DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=16),
        timeout=60.0,
    )
    _client_cache = (opensearch_url, username, password, client)
    atexit.register(client.close)
    return opensearch_url, client


# Keep backwards-compatible alias used by list_indices in cli_loop.py
_opensearch_session = _opensearch_client


def query_opensearch(body: dict, params: dict) -> dict:
    """Submit a synchronous query to OpenSearch.

    Raises OpenSearchConnectionError or OpenSearchAuthError on failure.
    """
    base_url, client = _opensearch_client()

    try:
        resp = client.post(
            base_url + "/api/console/proxy",
            params=params,
            json=body,
        )
    except httpx.RequestError as exc:
        raise OpenSearchConnectionError(
            f"Cannot reach OpenSearch at {base_url} — are you on the VPN? ({exc})"
        ) from exc

    if resp.status_code == 401:
        raise OpenSearchAuthError(
            "OpenSearch rejected the credentials — check PISCES_USERNAME/PASSWORD"
        )

    if not resp.is_success:
        raise OpenSearchConnectionError(
            f"OpenSearch returned HTTP {resp.status_code}: {resp.text[:300]}"
        )

    return resp.json()


# ---------------------------------------------------------------------------
# Async client (cross-protocol fan-out on the web path)
# ---------------------------------------------------------------------------

_async_client_cache: tuple[str, str, str, httpx.AsyncClient] | None = None


async def _get_async_client() -> tuple[str, httpx.AsyncClient]:
    """Return (base_url, long-lived AsyncClient) — one per process per credential set."""
    global _async_client_cache

    opensearch_url = os.environ.get("OPENSEARCH_URL", OPENSEARCH_URL)
    username = os.environ.get("PISCES_USERNAME", "")
    password = os.environ.get("PISCES_PASSWORD", "")

    if not username or not password:
        raise OpenSearchConnectionError(
            "PISCES_USERNAME and PISCES_PASSWORD must be set — check your .env file"
        )

    if _async_client_cache is not None:
        cached_url, cached_user, cached_pass, cached_client = _async_client_cache
        if (cached_url, cached_user, cached_pass) == (opensearch_url, username, password):
            return opensearch_url, cached_client

    async_client = httpx.AsyncClient(
        auth=(username, password),
        verify=False,
        headers=_DEFAULT_HEADERS,
        limits=httpx.Limits(max_connections=40, max_keepalive_connections=32),
        timeout=60.0,
    )
    _async_client_cache = (opensearch_url, username, password, async_client)
    return opensearch_url, async_client


async def query_opensearch_async(body: dict, params: dict) -> dict:
    """Async variant of query_opensearch — for use in the web fan-out path.

    Raises OpenSearchConnectionError or OpenSearchAuthError on failure.
    """
    base_url, client = await _get_async_client()

    try:
        resp = await client.post(
            base_url + "/api/console/proxy",
            params=params,
            json=body,
        )
    except httpx.RequestError as exc:
        raise OpenSearchConnectionError(
            f"Cannot reach OpenSearch at {base_url} — are you on the VPN? ({exc})"
        ) from exc

    if resp.status_code == 401:
        raise OpenSearchAuthError(
            "OpenSearch rejected the credentials — check PISCES_USERNAME/PASSWORD"
        )

    if not resp.is_success:
        raise OpenSearchConnectionError(
            f"OpenSearch returned HTTP {resp.status_code}: {resp.text[:300]}"
        )

    return resp.json()
