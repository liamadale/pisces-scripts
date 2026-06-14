"""Threat model generator modules for PISCES Mantis ticket analysis.

Each module produces one output registry from the ticket index:
  dns_resolvers   → dns_resolver_ips.json
  infrastructure  → known_infra_ips.json
  malicious       → malicious_ips.json
  false_positives → false_positive_ips.json
  undetermined    → undetermined_ips.json
"""

from src.mantis.threat_model.dns_resolvers import generate_dns_resolver_registry
from src.mantis.threat_model.false_positives import generate_fp_candidates
from src.mantis.threat_model.infrastructure import generate_infra_registry
from src.mantis.threat_model.malicious import generate_threat_db
from src.mantis.threat_model.private_ip_profiles import profile_private_ips
from src.mantis.threat_model.undetermined import (
    enrich_undetermined_ips,
    generate_undetermined_registry,
)

__all__ = [
    "generate_dns_resolver_registry",
    "generate_fp_candidates",
    "generate_infra_registry",
    "generate_threat_db",
    "generate_undetermined_registry",
    "enrich_undetermined_ips",
    "profile_private_ips",
]
