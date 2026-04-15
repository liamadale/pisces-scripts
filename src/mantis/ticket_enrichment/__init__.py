"""Rule-based ticket classification pipeline with optional NLP.

Public API:
    classify(ticket)              -> ClassificationResult
    classify_rules(ticket)        -> ClassificationResult
    OfflineEnrichment             -- structured offline enrichment hints
    OfflineEnrichmentProvider     -- aggregates offline signals for a ticket
    nlp                           -> NLP helper module (graceful fallback)
"""

from . import nlp
from .categories import Actor, Disposition, ThreatType
from .classifier import (
    ClassificationResult,
    classify,
    classify_rules,
    is_known_dns_resolver,
)
from .offline import OfflineEnrichment, OfflineEnrichmentProvider

__all__ = [
    "Disposition",
    "ThreatType",
    "Actor",
    "classify",
    "classify_rules",
    "ClassificationResult",
    "is_known_dns_resolver",
    "OfflineEnrichment",
    "OfflineEnrichmentProvider",
    "nlp",
]
