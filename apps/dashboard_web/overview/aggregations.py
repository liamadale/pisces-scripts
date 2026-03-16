"""Overview aggregation — cross-app stat row data."""

import collections
import concurrent.futures

from apps.mantis_web.data import (
    MALICIOUS_ROWS, FP_ROWS, TICKETS_BY_IP, _raw_tickets,
    MALICIOUS_BY_IP, FP_BY_IP,
)
from apps.dashboard_web.opensearch.aggregations import agg_opensearch_sensors, agg_opensearch_notice_count
from apps.dashboard_web.kibana.aggregations import agg_kibana_severity


def agg_cross_source_ips(time_range: str, limit: int = 25) -> dict:
    """Top IPs from each backend as two independent ranked lists.

    opensearch — top `limit` IPs by Zeek log hit count (public only),
                 sorted by total hit count descending.
    kibana     — top `limit` IPs sorted by Sev 1 desc → Sev 2 desc → total,
                 so high-confidence alerts surface above Sev 3 noise floods.
    """
    from apps.opensearch_web.queries import run_cross_protocol_query
    from src.querier.kibana_module import get_ip_severity_overview
    from src.utils.ip_org import lookup_org

    def fetch_os():
        rows = run_cross_protocol_query({
            "time_range": time_range, "sensor": "all", "limit": 500,
            "public_only": True, "src_ip": None, "direction": None,
            "min_risk_score": None, "no_filters": False, "use_cache": True,
        })
        return {r["src_ip"]: r["total"] for r in rows}

    def fetch_kibana():
        rows = get_ip_severity_overview({"time_range": time_range, "no_filters": False})
        return {r["src_ip"]: r for r in rows}

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f_os = ex.submit(fetch_os)
        f_kb = ex.submit(fetch_kibana)
        os_counts = f_os.result()
        kb_data   = f_kb.result()

    def _verdict(ip):
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
        os_rows.append({
            "ip":         ip,
            "os_count":   os_n,
            "verdict":    verdict,
            "tickets":    len(TICKETS_BY_IP.get(ip, [])),
            "attack_str": attack_str,
            "org_name":   org["name"] if org else "",
            "org_icon":   org["icon"] if org else "",
        })
    os_rows.sort(key=lambda r: -r["os_count"])

    kb_rows = []
    for ip, kb in kb_data.items():
        verdict, attack_str = _verdict(ip)
        org = lookup_org(ip)
        kb_rows.append({
            "ip":         ip,
            "kb_sev1":    kb.get("sev1", 0),
            "kb_sev2":    kb.get("sev2", 0),
            "kb_sev3":    kb.get("sev3", 0),
            "kb_total":   kb.get("total", 0),
            "top_sig":    kb.get("top_sig", ""),
            "verdict":    verdict,
            "tickets":    len(TICKETS_BY_IP.get(ip, [])),
            "attack_str": attack_str,
            "org_name":   org["name"] if org else "",
            "org_icon":   org["icon"] if org else "",
        })
    # Sev 1 first, then Sev 2, then raw total — surfaces quality over noise
    kb_rows.sort(key=lambda r: (-r["kb_sev1"], -r["kb_sev2"], -r["kb_total"]))

    return {
        "opensearch": os_rows[:limit],
        "kibana":     kb_rows[:limit],
    }


def agg_overview(time_range: str) -> dict:
    """Stat row data + verdict counts + cross-source IP table for the Overview section."""
    malicious_count = len(MALICIOUS_ROWS)
    fp_count = len(FP_ROWS)
    total_tickets = len(_raw_tickets)

    all_ticket_ips = set(TICKETS_BY_IP.keys())
    malicious_ips_set = {r["ip"] for r in MALICIOUS_ROWS}
    fp_ips_set = {r["ip"] for r in FP_ROWS}
    observed_only = len(all_ticket_ips - malicious_ips_set - fp_ips_set)

    counter = collections.Counter()
    for row in MALICIOUS_ROWS:
        for at in row.get("attack_types", []):
            counter[at] += 1
    top_attack = counter.most_common(1)
    top_attack_type = top_attack[0][0].replace("_", " ").title() if top_attack else "—"

    # Run sensors, kibana severity, notice count, and cross-source table in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        f_sensors = ex.submit(agg_opensearch_sensors, time_range)
        f_sev     = ex.submit(agg_kibana_severity, time_range)
        f_notices = ex.submit(agg_opensearch_notice_count, time_range)
        f_table   = ex.submit(agg_cross_source_ips, time_range)
        sensors_data         = f_sensors.result()
        sev_data             = f_sev.result()
        opensearch_notice_count = f_notices.result()
        cross_source_ips     = f_table.result()

    active_sensors     = len(sensors_data["labels"])
    kibana_alert_count = sev_data["sev1"] + sev_data["sev2"] + sev_data["sev3"]

    return {
        "total_tickets":          total_tickets,
        "malicious_count":        malicious_count,
        "fp_count":               fp_count,
        "active_sensors":         active_sensors,
        "kibana_alert_count":     kibana_alert_count,
        "opensearch_notice_count": opensearch_notice_count,
        "top_attack_type":        top_attack_type,
        "verdict": {
            "malicious": malicious_count,
            "fp":        fp_count,
            "observed":  observed_only,
        },
        "cross_source_ips": cross_source_ips,
    }
