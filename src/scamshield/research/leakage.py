"""Formal leakage audit for the ScamShield dataset.

Detects and reports both exact-text and normalised-text overlap across
train/validation/test splits, broken down by pair and by three-way overlap.
The original dataset files are never modified; all analysis is read-only.

The audit distinguishes:
- *exact* overlap: identical raw text strings across splits
- *normalised* overlap: text that is identical after ML preprocessing
  (Unicode NFC, case folding, URL anonymisation, whitespace collapse)

Normalised overlap is the stronger signal because it captures near-duplicates
arising from minor whitespace or casing differences across the synthetic
template outputs.
"""
from __future__ import annotations

from ..ml.preprocessing import preprocess


def audit_leakage(
    train: list[dict],
    validation: list[dict],
    test: list[dict],
) -> dict:
    """Compute exact and normalised text overlap between all split pairs.

    Args:
        train, validation, test: lists of record dicts, each with a "text" key.

    Returns a dict with:
        - exact_overlap:  {pair: [texts], ...}
        - normalised_overlap: {pair: [norm_texts], ...}
        - totals: {exact: int, normalised: int}
        - in_all_three_exact: [...]
        - in_all_three_normalised: [...]
        - overlap_type: "exact" | "normalised" | "mixed"
        - affected_split_pairs: list[str]
        - recommendation: str
    """
    # --- normalised keys ---
    norm_train = {preprocess(r["text"]): r["text"] for r in train}
    norm_valid = {preprocess(r["text"]): r["text"] for r in validation}
    norm_test  = {preprocess(r["text"]): r["text"] for r in test}

    # --- exact keys ---
    ex_train = {r["text"] for r in train}
    ex_valid = {r["text"] for r in validation}
    ex_test  = {r["text"] for r in test}

    def _pair(a: set, b: set) -> list[str]:
        return sorted(a & b)

    # normalised overlap
    nv_train_valid = _pair(set(norm_train), set(norm_valid))
    nv_train_test  = _pair(set(norm_train), set(norm_test))
    nv_valid_test  = _pair(set(norm_valid), set(norm_test))
    nv_all3        = sorted(set(norm_train) & set(norm_valid) & set(norm_test))

    # exact overlap
    ex_train_valid = _pair(ex_train, ex_valid)
    ex_train_test  = _pair(ex_train, ex_test)
    ex_valid_test  = _pair(ex_valid, ex_test)
    ex_all3        = sorted(ex_train & ex_valid & ex_test)

    norm_total = len(set(nv_train_valid) | set(nv_train_test) | set(nv_valid_test))
    exact_total = len(set(ex_train_valid) | set(ex_train_test) | set(ex_valid_test))

    affected_pairs: list[str] = []
    for pair, vals in [
        ("train-validation", nv_train_valid),
        ("train-test",       nv_train_test),
        ("validation-test",  nv_valid_test),
    ]:
        if vals:
            affected_pairs.append(pair)

    if norm_total == 0 and exact_total == 0:
        overlap_type = "none"
    elif norm_total == exact_total:
        overlap_type = "exact"
    elif exact_total < norm_total:
        overlap_type = "normalised"
    else:
        overlap_type = "mixed"

    recommendation = (
        "No leakage detected. The existing train/validation/test separation "
        "is clean."
        if overlap_type == "none"
        else (
            f"{norm_total} normalised text(s) appear in more than one split. "
            "To obtain a leakage-clean evaluation, exclude test rows whose "
            "normalised text appears in train or validation before computing "
            "held-out metrics. The original dataset files must not be modified; "
            "the leakage is detected and reported, and a leakage-clean "
            "evaluation subset can be derived at runtime."
        )
    )

    return {
        "exact_overlap": {
            "train-validation": ex_train_valid,
            "train-test":       ex_train_test,
            "validation-test":  ex_valid_test,
        },
        "normalised_overlap": {
            "train-validation": nv_train_valid,
            "train-test":       nv_train_test,
            "validation-test":  nv_valid_test,
        },
        "in_all_three_exact": ex_all3,
        "in_all_three_normalised": nv_all3,
        "totals": {"exact": exact_total, "normalised": norm_total},
        "overlap_type": overlap_type,
        "affected_split_pairs": affected_pairs,
        "recommendation": recommendation,
    }


def leakage_clean_records(
    test_records: list[dict],
    train_records: list[dict],
    validation_records: list[dict],
) -> list[dict]:
    """Return test records whose normalised text does NOT appear in train or
    validation. The original lists are never modified.

    This provides a runtime leakage-clean evaluation subset without rebuilding
    the frozen test split.
    """
    forbidden = {
        preprocess(r["text"]) for r in train_records
    } | {
        preprocess(r["text"]) for r in validation_records
    }
    return [r for r in test_records if preprocess(r["text"]) not in forbidden]
