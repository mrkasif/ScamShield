"""Language and scam-category stratified evaluation.

Provides per-language and per-category metric breakdowns on labelled
records using a pre-computed prediction list. The predictor is NOT called
again — the predictions were already computed by the caller (typically the
combined evaluator in runner.py) and are passed in.

This keeps the stratified functions pure and avoids redundant analyse()
calls. No network, no model changes, no file writes.
"""
from __future__ import annotations

from .metrics import classification_metrics

_MIN_SAMPLES_FOR_METRICS = 5  # minimum per-group n to compute metrics

# Mapping: analyzer scam_type → dataset scam_type
# (they use different vocabularies; this normalises the analyzer output to
# the dataset schema for per-category comparison.)
ANALYZER_TO_DATASET_CATEGORY: dict[str, str] = {
    "fake_kyc":                      "kyc",
    "upi_payment":                   "upi_payment",
    "phishing":                      "phishing",
    "bank_impersonation":            "bank_impersonation",
    "government_impersonation":      "government_impersonation",
    "credential_theft":              "credential_theft",
    "fake_customer_care":            "customer_care",
    "job_scam":                      "job",
    "investment_scam":               "investment",
    "loan_scam":                     "loan",
    "delivery_scam":                 "delivery",
    "lottery_prize":                 "lottery",
    "social_media_impersonation":    "social_impersonation",
    "other":                         "other",
    "safe":                          "safe",
}


def by_language(
    records: list[dict],
    predictions: list[str],
    *,
    min_samples: int = _MIN_SAMPLES_FOR_METRICS,
) -> dict:
    """Compute per-language evaluation breakdown.

    Args:
        records: list of dicts with "language" and "scam_or_safe" (true label).
        predictions: parallel list of predicted labels ("scam" / "safe").

    Returns::

        {
            "available": True,
            "languages": {
                "en": {"n": ..., "distribution": ..., "metrics": ...},
                ...
            },
            "note": str,
        }

    Languages with fewer than `min_samples` rows have metrics=None and a note.
    """
    from collections import defaultdict, Counter

    groups: dict[str, dict[str, list[str]]] = defaultdict(lambda: {"labels": [], "preds": []})
    for rec, pred in zip(records, predictions):
        lang = rec.get("language", "unknown")
        groups[lang]["labels"].append(rec.get("scam_or_safe", ""))
        groups[lang]["preds"].append(pred)

    result: dict[str, dict] = {}
    for lang, data in sorted(groups.items()):
        labels, preds = data["labels"], data["preds"]
        n = len(labels)
        dist = Counter(labels)
        entry: dict = {"n": n, "distribution": dict(dist), "metrics": None}
        if n >= min_samples:
            entry["metrics"] = classification_metrics(labels, preds)
        else:
            entry["note"] = (
                f"Only {n} sample(s) — below the {min_samples}-sample "
                "minimum; metrics are not reported."
            )
        result[lang] = entry

    langs_below = [l for l, d in result.items() if d["metrics"] is None]
    note = (
        "All language groups meet the minimum sample threshold."
        if not langs_below
        else f"Languages below minimum ({', '.join(sorted(langs_below))}) "
             "have metrics=None for statistical reliability."
    )
    return {"available": True, "languages": result, "note": note}


def by_category(
    records: list[dict],
    predictions: list[str],
    *,
    min_samples: int = _MIN_SAMPLES_FOR_METRICS,
) -> dict:
    """Compute per-category one-vs-rest evaluation breakdown.

    For each dataset scam_type (except 'safe'), compute:
      TP = rows with that category correctly predicted as scam
      FN = rows with that category predicted as safe
      FP = rows of other categories predicted as this category
      TN = rows neither in category nor predicted as category

    From these, derive accuracy / precision / recall / F1 for each category.
    Categories with fewer than `min_samples` rows are skipped (not computed).
    Only categories present in the dataset are included; the evaluator never
    invents missing categories.
    """
    # Group by normalised dataset scam_type (already in schema)
    from collections import defaultdict

    categories: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for rec, pred in zip(records, predictions):
        cat = rec.get("scam_type", "safe")
        true_label = rec.get("scam_or_safe", "")
        categories[cat].append((true_label, pred))

    result: dict[str, dict] = {}
    all_cats = sorted(categories.keys())

    for cat in all_cats:
        if cat == "safe":
            continue
        entries = categories[cat]
        n = len(entries)
        if n < min_samples:
            continue
        tp = sum(1 for t, p in entries if t == "scam" and p == "scam")
        fn = sum(1 for t, p in entries if t == "scam" and p == "safe")
        fp = sum(1 for cat2, entries2 in categories.items()
                 if cat2 != cat
                 for t, p in entries2 if p == "scam")
        # TN: rows not in this category, predicted safe
        tn = sum(1 for cat2, entries2 in categories.items()
                 if cat2 != cat
                 for t, p in entries2 if p == "safe")
        total = tp + fp + tn + fn
        accuracy  = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp)   if (tp + fp) else 0.0
        recall    = tp / (tp + fn)   if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

        result[cat] = {
            "n": n,
            "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "accuracy":  round(accuracy,  4),
            "precision": round(precision, 4),
            "recall":    round(recall,    4),
            "f1":        round(f1,        4),
        }

    note = (
        f"{len(result)} of {len(all_cats)} non-safe categories have enough "
        "samples for per-category metrics."
        if result
        else "No non-safe category has enough samples for per-category metrics."
    )
    return {"available": True, "categories": result, "note": note,
            "analyser_to_dataset_map": ANALYZER_TO_DATASET_CATEGORY}
