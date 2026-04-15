"""Overview aggregation — cross-app stat row data."""

import collections
import concurrent.futures

from apps.mantis_web.data import (
    MALICIOUS_ROWS,
    FP_ROWS,
    TICKETS_BY_IP,
    _raw_tickets,
    MALICIOUS_BY_IP,
    FP_BY_IP,
)
from apps.dashboard_web.opensearch.aggregations import (
    agg_opensearch_sensors,
    agg_opensearch_notice_count,
)


def agg_cross_source_ips(time_range: str, limit: int = 25) -> dict:
    """Top IPs from OpenSearch as a ranked list.

    opensearch — top `limit` IPs by Zeek log hit count (public only),
                 sorted by total hit count descending.
    """
    from apps.opensearch_web.queries import run_cross_protocol_query
    from src.utils.ip_org import lookup_org

    rows = run_cross_protocol_query(
        {
            "time_range": time_range,
            "sensor": "all",
            "limit": 500,
            "public_only": True,
            "src_ip": None,
            "direction": None,
            "min_risk_score": None,
            "no_filters": False,
            "use_cache": True,
        }
    )
    os_counts = {r["src_ip"]: r["total"] for r in rows}

    def _verdict(ip: str) -> tuple[str, str]:
        if ip in MALICIOUS_BY_IP:
            m = MALICIOUS_BY_IP[ip]
            attack_str = ", ".join(
                a.replace("_", " ").title() for a in m.get("attack_types", [])
            )
            return "malicious", attack_str
        if ip in FP_BY_IP:
            return "fp", ""
        if TICKETS_BY_IP.get(ip):
            return "observed", ""
        return "unknown", ""

    os_rows = []
    for ip, os_n in os_counts.items():
        verdict, attack_str = _verdict(ip)
        org = lookup_org(ip)
        os_rows.append(
            {
                "ip": ip,
                "os_count": os_n,
                "verdict": verdict,
                "tickets": len(TICKETS_BY_IP.get(ip, [])),
                "attack_str": attack_str,
                "org_name": org["name"] if org else "",
                "org_icon": org["icon"] if org else "",
            }
        )
    os_rows.sort(key=lambda r: -r["os_count"])

    return {"opensearch": os_rows[:limit]}


def agg_overview(time_range: str) -> dict:
    """Stat row data + verdict counts + cross-source IP table for the Overview section."""
    malicious_count = len(MALICIOUS_ROWS)
    fp_count = len(FP_ROWS)
    total_tickets = len(_raw_tickets)

    all_ticket_ips = set(TICKETS_BY_IP.keys())
    malicious_ips_set = {r["ip"] for r in MALICIOUS_ROWS}
    fp_ips_set = {r["ip"] for r in FP_ROWS}
    observed_only = len(all_ticket_ips - malicious_ips_set - fp_ips_set)

    counter: collections.Counter = collections.Counter()
    for row in MALICIOUS_ROWS:
        for at in row.get("attack_types", []):
            counter[at] += 1
    top_attack = counter.most_common(1)
    top_attack_type = top_attack[0][0].replace("_", " ").title() if top_attack else "—"

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        f_sensors = ex.submit(agg_opensearch_sensors, time_range)
        f_notices = ex.submit(agg_opensearch_notice_count, time_range)
        f_table = ex.submit(agg_cross_source_ips, time_range)
        sensors_data = f_sensors.result()
        opensearch_notice_count = f_notices.result()
        cross_source_ips = f_table.result()

    active_sensors = len(sensors_data["labels"])

    return {
        "total_tickets": total_tickets,
        "malicious_count": malicious_count,
        "fp_count": fp_count,
        "active_sensors": active_sensors,
        "opensearch_notice_count": opensearch_notice_count,
        "top_attack_type": top_attack_type,
        "verdict": {
            "malicious": malicious_count,
            "fp": fp_count,
            "observed": observed_only,
        },
        "cross_source_ips": cross_source_ips,
    }
