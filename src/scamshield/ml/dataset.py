"""Dataset loading, validation and hygiene for the ScamShield ML layer.

Reads the existing labelled splits produced by the dataset build step
(`data/{train,validation,test}/messages.csv` and the combined
`data/processed/messages.csv`) and validates them against the documented
schema before they are used for ML training.

Responsibilities:
  * load a CSV into a list of records
  * validate the required columns and that there is a binary label column
  * validate label values (normalized 'scam'/'safe')
  * remove exact duplicates safely (text normalised for comparison)
  * detect obvious leakage (same text appearing across train/val/test)
  * report class distribution

This module never invents or relabels data: if a label value is not in the
expected vocabulary it raises an error rather than silently mapping it.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from .preprocessing import preprocess

# Column names expected in the dataset (see data/schema.md).
REQUIRED_COLUMNS = [
    "id",
    "text",
    "language",
    "scam_or_safe",
    "scam_type",
]

LABEL_COLUMN = "scam_or_safe"

# Expected binary label values (already normalized).
VALID_LABELS = frozenset({"scam", "safe"})

# Optional column that carries the finer-grained category as metadata.
SCAM_TYPE_COLUMN = "scam_type"


def _read_csv(path: Path) -> list[dict]:
    """Read a CSV into a list of dict rows (utf-8-sig to strip a BOM)."""
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def validate_schema(rows: list[dict], path=None) -> dict:
    """Validate that required columns are present and return their header."""
    if not rows:
        raise ValueError("Dataset is empty - no rows to validate.")
    missing = [c for c in REQUIRED_COLUMNS if c not in rows[0]]
    if missing:
        context = f" in {path}" if path else ""
        raise ValueError(
            f"Dataset{context} is missing required column(s): {missing}. "
            f"Expected at least: {REQUIRED_COLUMNS}."
        )
    return rows[0]


def validate_labels(rows: list[dict], path=None) -> None:
    """Check every row's label is a normalized binary value."""
    context = f" in {path}" if path else ""
    bad = {}
    for row in rows:
        label = row.get(LABEL_COLUMN)
        if label not in VALID_LABELS:
            bad[label] = bad.get(label, 0) + 1
    if bad:
        raise ValueError(
            f"Unexpected label value(s){context}: {bad}. "
            "Only 'scam' and 'safe' are accepted; refusing to relabel."
        )


def class_distribution(rows: list[dict]) -> dict:
    """Return {label: count} over the binary label column."""
    return dict(Counter(r.get(LABEL_COLUMN) for r in rows))


def to_simple_records(rows: list[dict]) -> list[dict]:
    """Project rows into {text, label, scam_type (meta)} for ML use."""
    records = []
    for row in rows:
        records.append(
            {
                "text": row.get("text") or "",
                "label": row.get(LABEL_COLUMN),
                "scam_type": row.get(SCAM_TYPE_COLUMN),
            }
        )
    return records


def remove_duplicates(records: list[dict]) -> list[dict]:
    """Remove exact text duplicates, keeping the first occurrence.

    Comparison is on the normalized (preprocessed) text so that two rows that
    differ only in whitespace/case/URL host are treated as the same message.
    The first-seen label is kept; this is safe because duplicate rows come
    from the same source with the same label in practice.
    """
    seen = set()
    out = []
    for record in records:
        key = preprocess(record["text"])
        if key in seen:
            continue
        seen.add(key)
        out.append(record)
    return out


def detect_leakage(
    train: list[dict], validation: list[dict], test: list[dict]
) -> dict:
    """Detect exact (normalized) text repeated across different splits.

    Returns a dict with the count of leaked rows and a summary of which pairs
    overlap. Leakage means the same message text appears in more than one
    split, which can inflate evaluation scores and must be reported/documented.
    """
    train_keys = {preprocess(r["text"]) for r in train}
    valid_keys = {preprocess(r["text"]) for r in validation}
    test_keys = {preprocess(r["text"]) for r in test}

    train_valid = train_keys & valid_keys
    train_test = train_keys & test_keys
    valid_test = valid_keys & test_keys
    all3 = train_keys & valid_keys & test_keys

    total = len(train_valid) + len(train_test) + len(valid_test)
    return {
        "leakage_detected": total > 0,
        "train_validation": sorted(train_valid),
        "train_test": sorted(train_test),
        "validation_test": sorted(valid_test),
        "in_all_three": sorted(all3),
        "total_leaked_texts": len(set(train_valid) | set(train_test) | set(valid_test)),
        "note": (
            "Same message text appears in multiple splits. For an honest "
            "baseline these should be deduplicated globally before splitting, "
            "but the frozen test split must not be rebuilt; leakage is detected "
            "and reported rather than silently ignored."
        ),
    }


def load_split(path) -> list[dict]:
    """Load, schema-validate, label-validate and dedupe one split file."""
    path = Path(path)
    rows = _read_csv(path)
    validate_schema(rows, path=path)
    validate_labels(rows, path=path)
    records = to_simple_records(rows)
    return remove_duplicates(records)


def load_all(
    root="data",
    *,
    train_file="train/messages.csv",
    validation_file="validation/messages.csv",
    test_file="test/messages.csv",
) -> dict:
    """Load all three splits with schema + label validation.

    Returns:
        {
            "train": [...], "validation": [...], "test": [...],
            "distribution": {...}, "leakage": {...},
        }
    """
    root = Path(root)
    train = load_split(root / train_file)
    validation = load_split(root / validation_file)
    test = load_split(root / test_file)
    leakage = detect_leakage(train, validation, test)
    distribution = {
        "train": class_distribution(train),
        "validation": class_distribution(validation),
        "test": class_distribution(test),
    }
    return {
        "train": train,
        "validation": validation,
        "test": test,
        "distribution": distribution,
        "leakage": leakage,
    }
