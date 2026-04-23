"""Build shareable PISCES and OpenSearch Dashboards URLs from search context.

Standalone utility — no Flask dependency. Reusable by web app, CLI, and MCP servers.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from urllib.parse import urlencode

import requests

DASHBOARDS_INDEX_PATTERN = os.environ.get("PISCES_DASHBOARDS_INDEX", "arkime_sessions3-*")

# ---------------------------------------------------------------------------
# ShareContext
# ---------------------------------------------------------------------------


@dataclass
class ShareContext:
    """Everything needed to reconstruct a PISCES or Dashboards URL."""

    src_ip: str | None = None
    dest_ip: str | None = None
    sensor: str | None = None
    time_from: str = ""
    time_to: str = ""
    log_type: str | None = None
    page_type: str = "overview"  # overview | log | ip_pivot
    extra_params: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Rison encoder (minimal subset for OpenSearch Dashboards URLs)
# ---------------------------------------------------------------------------

# Characters safe to leave unquoted in Rison strings.
# Conservative set: only identifiers that Dashboards won't misparse.
_RISON_SAFE = re.compile(r"^[a-zA-Z0-9_.~\-]+$")


def rison_encode(obj: object) -> str:
    """Encode a Python object to Rison format.

    Covers: dict, list, str, bool, int, float, None.
    """
    if obj is None:
        return "!n"
    if isinstance(obj, bool):
        return "!t" if obj else "!f"
    if isinstance(obj, int | float):
        return str(obj)
    if isinstance(obj, str):
        if _RISON_SAFE.match(obj):
            return obj
        escaped = obj.replace("!", "!!").replace("'", "!'")
        return f"'{escaped}'"
    if isinstance(obj, list):
        return "!(" + ",".join(rison_encode(v) for v in obj) + ")"
    if isinstance(obj, dict):
        pairs = ",".join(f"{rison_encode(k)}:{rison_encode(v)}" for k, v in obj.items())
        return f"({pairs})"
    return str(obj)


# ---------------------------------------------------------------------------
# KQL builder
# ---------------------------------------------------------------------------

# Core fields shared by all modules
SHARE_FIELD_MAP: dict[str, str] = {
    "src_ip": "source.ip",
    "dest_ip": "destination.ip",
    "sensor": "host.name",
}

# Protocol-specific fields — (log_type, param_name) → OpenSearch field
SHARE_EXTRA_FIELDS: dict[tuple[str, str], str] = {
    ("notice", "notice_note"): "zeek.notice.note",
    ("suricata_alert", "severity"): "suricata.alert.severity",
    ("suricata_alert", "sid"): "rule.id",
    ("suricata_alert", "rule_name"): "rule.name",
    ("suricata_alert", "rule_category"): "rule.category",
    ("dns", "dns_query"): "zeek.dns.query",
    ("dns", "rcode"): "zeek.dns.rcode_name",
    ("dns", "qtype"): "zeek.dns.qtype_name",
    ("http", "http_method"): "zeek.http.method",
    ("http", "http_host"): "zeek.http.host",
    ("http", "http_uri"): "zeek.http.uri",
    ("http", "status_code"): "zeek.http.status_code",
    ("ssh", "ssh_auth_result"): "zeek.ssh.auth_success",
    ("ssl", "ssl_sni"): "zeek.ssl.server_name",
    ("rdp", "rdp_result"): "zeek.rdp.result",
    ("rdp", "rdp_cookie"): "zeek.rdp.cookie",
    ("weird", "weird_name"): "zeek.weird.name",
    ("kerberos", "client"): "zeek.kerberos.client",
    ("kerberos", "service"): "zeek.kerberos.service",
    ("ntlm", "username"): "zeek.ntlm.username",
    ("radius", "username"): "zeek.radius.username",
    ("ftp", "user"): "zeek.ftp.user",
    ("modbus", "function"): "zeek.modbus.function",
    ("dnp3", "function"): "zeek.dnp3.function_request",
    ("smb", "smb_share"): "zeek.smb_files.path",
    ("smb", "smb_action"): "zeek.smb_files.action",
    ("tunnel", "tunnel_type"): "zeek.tunnel.tunnel_type",
    ("sip", "method"): "zeek.sip.method",
    ("sip", "user_agent"): "zeek.sip.user_agent",
}

# Suricata uses DATASETS=["alert"] + event.module:suricata, not event.dataset:suricata_alert
_SURICATA_LOG_TYPE = "suricata_alert"

# Default Discover columns per log type. Used when no explicit columns are provided.
_BASE_COLS = ["source.ip", "destination.ip", "destination.port"]

DISCOVER_COLUMNS: dict[str, list[str]] = {
    "conn": [
        *_BASE_COLS,
        "network.transport",
        "network.protocol",
        "zeek.conn.duration",
        "zeek.conn.conn_state",
    ],
    "dns": [*_BASE_COLS, "zeek.dns.query", "zeek.dns.qtype_name", "zeek.dns.rcode_name"],
    "http": [
        *_BASE_COLS,
        "zeek.http.method",
        "zeek.http.host",
        "zeek.http.uri",
        "zeek.http.status_code",
    ],
    "ssl": [*_BASE_COLS, "zeek.ssl.server_name", "zeek.ssl.version", "zeek.ssl.validation_status"],
    "ssh": [*_BASE_COLS, "zeek.ssh.auth_success", "zeek.ssh.client", "zeek.ssh.server"],
    "smtp": [*_BASE_COLS, "zeek.smtp.mailfrom", "zeek.smtp.rcptto", "zeek.smtp.subject"],
    "rdp": [*_BASE_COLS, "zeek.rdp.cookie", "zeek.rdp.result"],
    "smb": [*_BASE_COLS, "zeek.smb_files.action", "zeek.smb_files.path", "zeek.smb_files.name"],
    "notice": [*_BASE_COLS, "zeek.notice.note", "zeek.notice.msg"],
    "weird": [*_BASE_COLS, "zeek.weird.name", "zeek.weird.addl"],
    "suricata_alert": [
        *_BASE_COLS,
        "rule.name",
        "rule.category",
        "suricata.alert.severity",
        "suricata.alert.action",
        "tags",
    ],
    "files": [*_BASE_COLS, "zeek.files.mime_type", "zeek.files.filename", "zeek.files.source"],
    "x509": ["zeek.x509.certificate.subject", "zeek.x509.certificate.issuer", "zeek.x509.san.dns"],
    "kerberos": [
        *_BASE_COLS,
        "zeek.kerberos.client",
        "zeek.kerberos.service",
        "zeek.kerberos.success",
    ],
    "ntlm": [*_BASE_COLS, "zeek.ntlm.username", "zeek.ntlm.domainname", "zeek.ntlm.success"],
    "radius": [*_BASE_COLS, "zeek.radius.username", "zeek.radius.result"],
    "ftp": [*_BASE_COLS, "zeek.ftp.user", "zeek.ftp.command", "zeek.ftp.reply_code"],
    "sip": [*_BASE_COLS, "zeek.sip.method", "zeek.sip.status_code", "zeek.sip.user_agent"],
    "dhcp": ["source.ip", "zeek.dhcp.host_name", "zeek.dhcp.mac", "zeek.dhcp.assigned_ip"],
    "ntp": [*_BASE_COLS, "zeek.ntp.mode", "zeek.ntp.version"],
    "tunnel": [*_BASE_COLS, "zeek.tunnel.tunnel_type"],
    "modbus": [*_BASE_COLS, "zeek.modbus.function"],
    "dnp3": [*_BASE_COLS, "zeek.dnp3.function_request"],
}

_DEFAULT_COLS = [*_BASE_COLS, "network.transport", "event.dataset"]


def build_kql(ctx: ShareContext) -> str:
    """Build a KQL query string from a ShareContext."""
    parts: list[str] = []

    # Dataset filter
    if ctx.log_type:
        if ctx.log_type == _SURICATA_LOG_TYPE:
            parts.append("event.module:suricata AND event.dataset:alert")
        else:
            parts.append(f"event.dataset:{ctx.log_type}")

    # Core fields
    if ctx.page_type == "ip_pivot" and ctx.src_ip:
        parts.append(f"(source.ip:{ctx.src_ip} OR destination.ip:{ctx.src_ip})")
    else:
        if ctx.src_ip:
            parts.append(f"source.ip:{ctx.src_ip}")
        if ctx.dest_ip:
            parts.append(f"destination.ip:{ctx.dest_ip}")

    if ctx.sensor and ctx.sensor.lower() != "all":
        sensors = [s.strip() for s in ctx.sensor.split(",")]
        if len(sensors) == 1:
            parts.append(f"host.name:{sensors[0]}")
        else:
            clause = " OR ".join(f"host.name:{s}" for s in sensors)
            parts.append(f"({clause})")

    # Protocol-specific extra params
    for key, val in ctx.extra_params.items():
        if not val:
            continue
        os_field = SHARE_EXTRA_FIELDS.get((ctx.log_type or "", key))
        if os_field:
            parts.append(f"{os_field}:{val}")

    return " AND ".join(parts)


# ---------------------------------------------------------------------------
# URL builders
# ---------------------------------------------------------------------------


def build_pisces_url(ctx: ShareContext, script_name: str = "") -> str:
    """Build a PISCES web app URL with absolute time range."""
    if ctx.page_type == "ip_pivot" and ctx.src_ip:
        path = f"{script_name}/ip/{ctx.src_ip}"
    elif ctx.page_type == "log" and ctx.log_type:
        path = f"{script_name}/log/{ctx.log_type}"
    else:
        path = f"{script_name}/"

    params: dict[str, str] = {}
    if ctx.time_from:
        params["from"] = ctx.time_from
    if ctx.time_to:
        params["to"] = ctx.time_to
    if ctx.sensor and ctx.sensor.lower() != "all":
        params["sensor"] = ctx.sensor
    if ctx.page_type != "ip_pivot" and ctx.src_ip:
        params["src_ip"] = ctx.src_ip
    for k, v in ctx.extra_params.items():
        if v:
            params[k] = str(v)

    return f"{path}?{urlencode(params)}" if params else path


def build_dashboards_path(
    ctx: ShareContext,
    columns: list[str] | None = None,
) -> str:
    """Build the Discover hash path (no protocol/host).

    Returns a path starting with ``/app/discover#/...`` suitable for both
    long URLs (prepend OPENSEARCH_URL) and the shorten API (pass directly).

    Args:
        ctx: Share context with query parameters.
        columns: Explicit Discover column list. If ``None``, uses sensible
            defaults from ``DISCOVER_COLUMNS`` based on ``ctx.log_type``.
    """
    kql = build_kql(ctx)

    if columns is None:
        columns = DISCOVER_COLUMNS.get(ctx.log_type or "", _DEFAULT_COLS)

    g_state = rison_encode({"time": {"from": ctx.time_from, "to": ctx.time_to}})
    a_state = rison_encode(
        {
            "columns": columns,
            "index": DASHBOARDS_INDEX_PATTERN,
            "query": {"language": "kuery", "query": kql},
        }
    )

    return f"/app/discover#/?_g={g_state}&_a={a_state}"


def shorten_dashboards_url(
    discover_path: str,
    dashboards_base: str,
    auth: tuple[str, str],
) -> str | None:
    """POST *discover_path* to ``/api/shorten_url``.

    Returns full short URL (``{dashboards_base}/goto/{urlId}``) or ``None`` on failure.
    """
    try:
        resp = requests.post(
            f"{dashboards_base}/api/shorten_url",
            json={"url": discover_path},
            headers={"osd-xsrf": "true"},
            auth=auth,
            timeout=10,
            verify=False,  # noqa: S501 — Malcolm uses self-signed certs
        )
        if resp.ok:
            url_id = resp.json().get("urlId")
            if url_id:
                return f"{dashboards_base}/goto/{url_id}"
    except Exception:
        pass
    return None
