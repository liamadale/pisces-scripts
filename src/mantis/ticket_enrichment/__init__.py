"""Hybrid ML + rule-based ticket classification pipeline.

Public API:
    classify(ticket)          -> ClassificationResult
    classify_rules(ticket)    -> ClassificationResult   (Layer 1 only)
    train_model(tickets)      -> None                   (Layer 2 training)
"""

from .categories import Disposition, ThreatType, Actor
from .classifier import classify, classify_rules, ClassificationResult, invalidate_model_cache
from .trainer import train_model

__all__ = [
    "Disposition", "ThreatType", "Actor",
    "classify", "classify_rules", "ClassificationResult",
    "train_model", "invalidate_model_cache",
]
