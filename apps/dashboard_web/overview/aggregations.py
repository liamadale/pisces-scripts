"""Overview aggregation — cross-app stat row data."""

import collections

from apps.mantis_web.data import MALICIOUS_ROWS, FP_ROWS, TICKETS_BY_IP, _raw_tickets
from apps.dashboard_web.opensearch.aggregations import agg_opensearch_sensors
from apps.dashboard_web.kibana.aggregations import agg_kibana_severity


def agg_overview(time_range: str) -> dict:
    """Stat row data + verdict counts for the Overview section."""
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

    sensors_data = agg_opensearch_sensors(time_range)
    active_sensors = len(sensors_data["labels"])

    sev_data = agg_kibana_severity(time_range)
    kibana_alert_count = sev_data["sev1"] + sev_data["sev2"] + sev_data["sev3"]

    return {
        "total_tickets": total_tickets,
        "malicious_count": malicious_count,
        "fp_count": fp_count,
        "active_sensors": active_sensors,
        "kibana_alert_count": kibana_alert_count,
        "top_attack_type": top_attack_type,
        "verdict": {
            "malicious": malicious_count,
            "fp": fp_count,
            "observed": observed_only,
        },
    }
