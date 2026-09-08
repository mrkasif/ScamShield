"""Dataset loading, profiling and hygiene for the research lab.

Loads all three labelled splits (train/validation/test) from CSV, validates
the schema, and provides a rich profile (class distribution, scam categories,
languages, sources) without mutating the original files. Deduplication is
applied using the same normalised-text logic as the ML pipeline so all
evaluation subsets are consistent.

This module reads files only; it never writes to the dataset.
"""
from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path

from ..ml.preprocessing import preprocess

REQUIRED_COLUMNS = [
    "id", "text", "language", "scam_or_safe", "scam_type", "source", "split",
]

# Subset of columns needed for evaluation (the CSV may have more).
EVAL_COLUMNS = [
    "id", "text", "language", "scam_or_safe", "scam_type", "source",
]


def _read_csv(path: Path) -> list[dict]:
    """Read a CSV into a list of dict rows (utf-8-sig to strip BOM)."""
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")
    with open(path, encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _validate_columns(rows: list[dict], path: Path) -> None:
    """Verify all EVAL_COLUMNS are present (informational; schema failures raise)."""
    if not rows:
        raise ValueError(f"Dataset is empty: {path}")
    headers = set(rows[0].keys())
    missing = [c for c in EVAL_COLUMNS if c not in headers]
    if missing:
        raise ValueError(
            f"Dataset {path} is missing required column(s): {missing}. "
            f"Expected at least: {EVAL_COLUMNS}."
        )


def _raw_records(rows: list[dict]) -> list[dict]:
    """Project rows to eval-relevant fields, preserving raw text."""
    out = []
    for row in rows:
        rec = {col: (row.get(col) or "").strip() for col in EVAL_COLUMNS}
        out.append(rec)
    return out


def _dedupe_records(records: list[dict]) -> list[dict]:
    """Remove text duplicates via normalised comparison (keep first)."""
    seen: set[str] = set()
    out = []
    for rec in records:
        key = preprocess(rec["text"])
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def load_split(path: str | Path) -> list[dict]:
    """Load, validate and return raw records for one split file (no dedup)."""
    path = Path(path)
    rows = _read_csv(path)
    _validate_columns(rows, path)
    return _raw_records(rows)


def load_dataset(
    root: str | Path = "data",
    *,
    train_file: str = "train/messages.csv",
    validation_file: str = "validation/messages.csv",
    test_file: str = "test/messages.csv",
) -> dict:
    """Load all three splits (raw + deduplicated) with a full profile.

    Returns::

        {
            "train_raw": [...], "validation_raw": [...], "test_raw": [...],
            "train": [...], "validation": [...], "test": [...],
            "profile": { distribution, categories, languages, sources },
        }

    All record dicts contain: id, text, language, scam_or_safe, scam_type, source.
    """
    root = Path(root)
    train_raw = _raw_records(_read_csv(root / train_file))
    valid_raw = _raw_records(_read_csv(root / validation_file))
    test_raw  = _raw_records(_read_csv(root / test_file))

    # Schema check after reading (informational)
    for split_name, path, rows in [
        ("train", root / train_file, train_raw),
        ("validation", root / validation_file, valid_raw),
        ("test", root / test_file, test_raw),
    ]:
        if not rows:
            raise ValueError(f"Split {split_name} ({path}) is empty.")
        _validate_columns(rows, path)

    train = _dedupe_records(train_raw)
    valid = _dedupe_records(valid_raw)
    test  = _dedupe_records(test_raw)

    def _split_profile(records: list[dict]) -> dict:
        dist = Counter(r["scam_or_safe"] for r in records)
        cats = Counter(r["scam_type"] for r in records)
        langs = Counter(r["language"] for r in records)
        srcs = Counter(r["source"] for r in records)
        return {"n": len(records), "distribution": dict(dist), "categories": dict(cats),
                "languages": dict(langs), "sources": dict(srcs)}

    profile = {
        "raw_counts": {
            "train": len(train_raw), "validation": len(valid_raw), "test": len(test_raw),
            "total": len(train_raw) + len(valid_raw) + len(test_raw),
        },
        "deduped_counts": {
            "train": len(train), "validation": len(valid), "test": len(test),
            "total": len(train) + len(valid) + len(test),
        },
        "train": _split_profile(train),
        "validation": _split_profile(valid),
        "test": _split_profile(test),
    }
    return {
        "train_raw": train_raw, "validation_raw": valid_raw, "test_raw": test_raw,
        "train": train, "validation": valid, "test": test,
        "profile": profile,
    }
