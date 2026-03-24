"""Layer 2: TF-IDF + LinearSVC model training and persistence.

Train on high-confidence Layer 1 classifications, predict ambiguous tickets.
Labels are Disposition values (4 classes): true_positive, benign_true_positive,
false_positive, undetermined.
Gracefully degrades if scikit-learn is not installed.
"""

from __future__ import annotations

import os

from .categories import Disposition

_BASE = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
DEFAULT_MODEL_PATH = os.path.join(
    _BASE, "data", "tickets", "models", "classifier_model.joblib"
)


def build_feature_text(ticket: dict) -> str:
    """Concatenate all text fields into a single feature string for TF-IDF."""
    parts = [
        ticket.get("summary", ""),
        ticket.get("description", "") or "",
        ticket.get("steps_to_reproduce", "") or "",
        ticket.get("additional_information", "") or "",
    ]
    for note in ticket.get("notes", []):
        parts.append(note.get("text", ""))
    return " ".join(parts)


def train_model(
    tickets: list[dict],
    model_path: str = DEFAULT_MODEL_PATH,
    min_confidence_score: int = 2,
) -> dict[str, int] | None:
    """Train a TF-IDF + LinearSVC classifier from high-confidence Layer 1 labels.

    Labels are Disposition values (4 classes) — simpler than category/subcategory,
    more training data per class, better generalization. Threat type is well-handled
    by ET parser rules and doesn't need ML.

    Only tickets with reputation outside the undetermined zone (<=30 or >=70) are
    used as training data, ensuring the model learns from clear signals only.

    Args:
        tickets: All tickets from the index
        model_path: Where to save the trained model
        min_confidence_score: Unused — kept for backward-compatible signature.
            The undetermined zone filter (30-70) replaces the old abs-score gate.

    Returns:
        Dict of {label: count} for training data distribution, or None if sklearn unavailable.
    """
    try:
        import joblib
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.svm import LinearSVC
    except ImportError:
        return None

    from .classifier import (
        classify_rules,
        REPUTATION_FP_THRESHOLD,
        REPUTATION_TP_THRESHOLD,
    )

    # Build training data from high-confidence Layer 1 classifications.
    # Skip tickets in the undetermined reputation zone (REPUTATION_TP_THRESHOLD < score
    # < REPUTATION_FP_THRESHOLD) — these are ambiguous and would pollute training data.
    texts: list[str] = []
    labels: list[str] = []

    for ticket in tickets:
        result = classify_rules(ticket)
        if result.disposition == Disposition.UNDETERMINED:
            continue
        if REPUTATION_TP_THRESHOLD < result.score < REPUTATION_FP_THRESHOLD:
            continue

        label = result.disposition.value
        texts.append(build_feature_text(ticket))
        labels.append(label)

    if len(texts) < 50:
        return None

    # Count label distribution
    from collections import Counter

    label_dist = dict(Counter(labels).most_common())

    # Filter out labels with too few examples (need at least 5 for meaningful training)
    label_counts = Counter(labels)
    filtered = [(t, lb) for t, lb in zip(texts, labels) if label_counts[lb] >= 5]
    if len(filtered) < 50:
        return None
    texts, labels = zip(*filtered)
    texts, labels = list(texts), list(labels)

    # Build label name mapping
    unique_labels = sorted(set(labels))
    label_to_idx = {lb: i for i, lb in enumerate(unique_labels)}
    y = [label_to_idx[lb] for lb in labels]

    # TF-IDF vectorization
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        min_df=2,
        max_df=0.95,
        sublinear_tf=True,
    )
    X = vectorizer.fit_transform(texts)

    # Train LinearSVC with balanced class weights
    clf = LinearSVC(
        class_weight="balanced",
        max_iter=5000,
        C=1.0,
    )
    clf.fit(X, y)

    # Save model
    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(
        {"vectorizer": vectorizer, "clf": clf, "label_names": unique_labels}, model_path
    )

    return label_dist


def load_model(model_path: str = DEFAULT_MODEL_PATH):
    """Load a trained model. Returns (vectorizer, clf, label_names) or None.

    If the loaded model has labels that aren't valid Disposition values
    (stale model from before the refactor), returns None.
    """
    try:
        import joblib
    except ImportError:
        return None

    if not os.path.exists(model_path):
        return None

    data = joblib.load(model_path)
    label_names = data["label_names"]

    # Validate labels are valid Disposition values
    for label in label_names:
        try:
            Disposition(label)
        except ValueError:
            return None

    return data["vectorizer"], data["clf"], label_names
