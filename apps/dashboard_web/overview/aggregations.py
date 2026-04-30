"""Overview aggregation — cross-app stat row data."""

import concurrent.futures

from apps.dashboard_web.opensearch.aggregations import (
    agg_new_ips_delta,
    agg_notice_over_time,
    agg_opensearch_sensors,
    agg_suricata_over_time,
)
from apps.mantis_web.data import (
    FP_BY_IP,
    FP_ROWS,
    MALICIOUS_BY_IP,
    MALICIOUS_ROWS,
    TICKETS_BY_IP,
    _raw_tickets,
)


def agg_cross_source_ips(time_range: str, sensors: list | None = None, limit: int = 25) -> dict:
    """Top IPs from OpenSearch as a ranked list.

    opensearch — top `limit` IPs by Zeek log hit count (public only),
                 sorted by total hit count descending.
    """
    from apps.opensearch_web.queries import run_cross_protocol_query
    from src.utils.ip_org import lookup_org

    sensor_str = ",".join(sensors) if sensors else "all"
    rows = run_cross_protocol_query(
        {
            "time_range": time_range,
            "sensor": sensor_str,
            "limit": 500,
            "public_only": True,
            "src_ip": None,
            "direction": None,
            "no_filters": False,
            "use_cache": True,
        }
    )
    os_counts = {r["src_ip"]: r for r in rows}

    def _verdict(ip: str) -> tuple[str, str]:
        if ip in MALICIOUS_BY_IP:
            m = MALICIOUS_BY_IP[ip]
            attack_str = ", ".join(a.replace("_", " ").title() for a in m.get("attack_types", []))
            return "malicious", attack_str
        if ip in FP_BY_IP:
            return "fp", ""
        if TICKETS_BY_IP.get(ip):
            return "observed", ""
        return "unknown", ""

    os_rows = []
    for ip, r in os_counts.items():
        verdict, attack_str = _verdict(ip)
        org = lookup_org(ip)
        pp = r.get("per_protocol", {})
        os_rows.append(
            {
                "ip": ip,
                "os_count": r["total"],
                "notices": pp.get("notice", 0),
                "suricata": pp.get("suricata_alert", 0),
                "verdict": verdict,
                "tickets": len(TICKETS_BY_IP.get(ip, [])),
                "attack_str": attack_str,
                "org_name": org["name"] if org else "",
                "org_icon": org["icon"] if org else "",
            }
        )
    os_rows.sort(key=lambda r: -r["os_count"])

    untriaged = [r for r in os_rows if r["verdict"] == "unknown"]
    no_ticket = [r for r in os_rows if r["tickets"] == 0]

    return {
        "opensearch": os_rows[:limit],
        "untriaged": untriaged[:15],
        "no_ticket": no_ticket[:15],
        "alerts_no_ticket": len(no_ticket),
        "total_ips": len(os_rows),
    }


def agg_overview(time_range: str, sensors: list | None = None) -> dict:
    """Stat row data + cross-source IP table for the Overview section."""
    malicious_count = len(MALICIOUS_ROWS)
    fp_count = len(FP_ROWS)
    total_tickets = len(_raw_tickets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_sensors = ex.submit(agg_opensearch_sensors, time_range)
        f_table = ex.submit(agg_cross_source_ips, time_range, sensors)
        f_notice_ts = ex.submit(agg_notice_over_time, time_range, sensors)
        f_suricata_ts = ex.submit(agg_suricata_over_time, time_range, sensors)
        f_new_ips = ex.submit(agg_new_ips_delta, time_range, sensors)
        sensors_data = f_sensors.result()
        cross_source_ips = f_table.result()
        notice_over_time = f_notice_ts.result()
        suricata_over_time = f_suricata_ts.result()
        new_ips_delta = f_new_ips.result()

    active_sensors = len(sensors_data["labels"])

    return {
        "total_tickets": total_tickets,
        "malicious_count": malicious_count,
        "fp_count": fp_count,
        "active_sensors": active_sensors,
        "notice_over_time": notice_over_time,
        "suricata_over_time": suricata_over_time,
        "new_ips_delta": new_ips_delta,
        "cross_source_ips": cross_source_ips,
    }
