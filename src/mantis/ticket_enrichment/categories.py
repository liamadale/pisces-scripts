"""Central type definitions and ET rule mappings.

Defines the three classification dimensions (Disposition, ThreatType, Actor)
and maps ET/Suricata rule prefixes to ThreatType values.
"""

from enum import Enum


class Disposition(str, Enum):
    TRUE_POSITIVE = "true_positive"  # Confirmed threat
    BENIGN_TRUE_POSITIVE = "benign_true_positive"  # Real activity, authorized/expected
    FALSE_POSITIVE = "false_positive"  # Alert fired incorrectly
    UNDETERMINED = "undetermined"  # Insufficient evidence


class ThreatType(str, Enum):
    PORT_SCAN = "port_scan"
    EXPLOIT = "exploit"
    BOTNET = "botnet"
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    WEB_ATTACK = "web_attack"
    DNS_ANOMALY = "dns_anomaly"
    DDOS = "ddos"
    DATA_EXFIL = "data_exfil"
    SPAM_PHISHING = "spam_phishing"
    BLOCKLIST_HIT = "blocklist_hit"
    POLICY_VIOLATION = "policy_violation"
    RECON = "recon"
    VULNERABILITY_SCAN = "vulnerability_scan"
    UNKNOWN = "unknown"


class Actor(str, Enum):
    # Government / authorized programs
    CISA_CYHY = "cisa_cyhy"
    SHADOWSERVER = "shadowserver"
    # Commercial internet scanners
    CENSYS = "censys"
    RAPID7 = "rapid7"
    QUALYS = "qualys"
    BINARYEDGE = "binaryedge"
    NETSPI = "netspi"
    STRETCHOID = "stretchoid"
    ONYPHE = "onyphe"
    LEAKIX = "leakix"
    NESSUS = "nessus"
    DNS_RESOLVER = "dns_resolver"
    OTHER = "other"


# ET/Suricata rule prefix → ThreatType
ET_CATEGORY_MAP: dict[str, ThreatType] = {
    "ET SCAN": ThreatType.PORT_SCAN,
    "ET EXPLOIT": ThreatType.EXPLOIT,
    "ET DROP": ThreatType.BLOCKLIST_HIT,
    "ET CINS": ThreatType.BLOCKLIST_HIT,
    "ET TROJAN": ThreatType.MALWARE,
    "ET MALWARE": ThreatType.MALWARE,
    "ET POLICY": ThreatType.POLICY_VIOLATION,
    "ET INFO": ThreatType.RECON,
    "ET DNS": ThreatType.DNS_ANOMALY,
    "ET WEB_SERVER": ThreatType.WEB_ATTACK,
    "ET WEB_CLIENT": ThreatType.WEB_ATTACK,
    "ET HUNTING": ThreatType.RECON,
    "ET ATTACK_RESPONSE": ThreatType.EXPLOIT,
    "ET CURRENT_EVENTS": ThreatType.MALWARE,
    "ET TOR": ThreatType.POLICY_VIOLATION,
    "ET P2P": ThreatType.POLICY_VIOLATION,
    "ET COMPROMISED": ThreatType.BLOCKLIST_HIT,
    "ET MOBILE_MALWARE": ThreatType.MALWARE,
    "ET PHISHING": ThreatType.SPAM_PHISHING,
    "ET SPAM": ThreatType.SPAM_PHISHING,
    "ET DDOS": ThreatType.DDOS,
    "ET DOS": ThreatType.DDOS,
}
