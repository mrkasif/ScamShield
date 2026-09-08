"""Deterministic binary-classification metrics.

Thin wrapper around the ML layer's evaluate_predictions for consistency,
plus helpers used by the stratified and comparison components.
"""
from __future__ import annotations

from ..ml.evaluate import evaluate_predictions

POSITIVE = "scam"
NEGATIVE = "safe"


def bool_to_label(flag: bool) -> str:
    """Map a boolean prediction to the string label 'scam' or 'safe'."""
    return POSITIVE if flag else NEGATIVE


def classification_metrics(labels: list, predictions: list) -> dict:
    """Compute accuracy / precision / recall / F1 / confusion matrix.

    `labels` and `predictions` must be str values ("scam" / "safe").
    Returns the same dict structure produced by ml.evaluate.evaluate_predictions.
    """
    return evaluate_predictions(labels, predictions)


def per_category_confusion(
    labels: list[str],
    predictions: list[str],
    category: str,
) -> dict:
    """One-vs-rest confusion for a single category string.

    TP = true category AND predicted category
    FN = true category but NOT predicted category
    FP = NOT true category but predicted category
    TN = neither true nor predicted as this category

    Returns {tp, fp, tn, fn, n} ready for per-category metrics.
    """
    tp = fp = tn = fn = 0
    for true, pred in zip(labels, predictions):
        t = true == category
        p = pred == category
        if t and p:
            tp += 1
        elif t and not p:
            fn += 1
        elif not t and p:
            fp += 1
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "n": tp + fp + tn + fn}
