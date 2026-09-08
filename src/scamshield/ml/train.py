"""Training pipeline for the ScamShield ML layer.

Run with (from the repo root):

    python -m src.scamshield.ml.train

Steps:
  1. load train / validation / test splits
  2. validate schema
  3. validate labels (only 'scam' / 'safe' accepted - never relabeled)
  4. remove exact duplicates safely (within each split)
  5. detect obvious leakage between splits (reported, not silenced)
  6. build TF-IDF features (word 1-2 grams + char 3-5 grams)
  7. train a linear classifier (Logistic Regression)
  8. evaluate on the validation split and the frozen test split
  9. persist the trained bundle under models/
 10. persist metrics.json + evaluation_report.md

The model is NOT retrained on every scan - it is trained once here and only
loaded (never re-fit) at prediction time.

Design notes
------------
* A linear model + TF-IDF is intentionally chosen as a reproducible baseline:
  it trains in seconds on a laptop, is fully offline, needs no GPU, and is far
  easier to audit than a deep model.
* We use Logistic Regression so we can expose a genuine model probability
  (labelled `model_probability`, not a safety-calibrated probability).
* The original frozen test split is used only for the final, reported
  evaluation - never for model selection.
* The deterministic rule engine is NOT replaced; ML is an additional layer.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from pathlib import Path

from . import dataset as ds
from . import evaluate as ev
from .preprocessing import preprocess

# scikit-learn is imported lazily so that importing the package does not
# require it until training actually runs.
def _sk():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import FeatureUnion, Pipeline
    from sklearn.preprocessing import FunctionTransformer
    return {
        "TfidfVectorizer": TfidfVectorizer,
        "LogisticRegression": LogisticRegression,
        "FeatureUnion": FeatureUnion,
        "Pipeline": Pipeline,
        "FunctionTransformer": FunctionTransformer,
    }


MODEL_NAME = "scamshield_ml_tfidf_logreg"
MODEL_FILENAME = "scamshield_tfidf.joblib"
DEFAULT_OUTPUT_DIR = Path("models")
DEFAULT_DATA_ROOT = Path("data")
RANDOM_STATE = 42


def build_tfidf_pipeline(max_features: int | None = 120000,
                         class_weight="balanced"):
    """Build the TF-IDF + Logistic Regression scikit-learn pipeline.

    Representation: word 1-2 grams AND character 3-5 grams (FeatureUnion).
    The character grams help with noisy, code-mixed, and transliterated text
    (Hinglish / Devanagari), where word boundaries are uncertain.

    A LogisticRegression (not SVM) is used so probabilities are available;
    `class_weight="balanced"` mitigates the safe/scam imbalance.
    """
    sk = _sk()
    TfidfVectorizer = sk["TfidfVectorizer"]
    word_tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=2,
        max_features=max_features,
        sublinear_tf=True,
        token_pattern=r"(?u)\b\w+\b",
    )
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=max_features,
        sublinear_tf=True,
    )
    combined = sk["FeatureUnion"]([("word", word_tfidf), ("char", char_tfidf)])
    classifier = sk["LogisticRegression"](
        max_iter=2000, class_weight=class_weight, random_state=RANDOM_STATE
    )
    return classifier, combined


def fit_model(records, vectorizer, classifier) -> tuple:
    """Fit a classifier given raw records [{text, label}] and a vectorizer."""
    texts = [preprocess(r["text"]) for r in records]
    labels = [r["label"] for r in records]
    X = vectorizer.fit_transform(texts)
    classifier.fit(X, labels)
    return X, labels


def split_features_labels(records, vectorizer) -> tuple:
    """Transform records into (X, y) using an already-fitted vectorizer."""
    texts = [preprocess(r["text"]) for r in records]
    X = vectorizer.transform(texts)
    y = [r["label"] for r in records]
    return X, y


def train_and_evaluate(
    train_records,
    validation_records,
    test_records,
    *,
    output_dir=DEFAULT_OUTPUT_DIR,
    save_artifacts=True,
    max_features: int | None = 120000,
    class_weight="balanced",
):
    """Train the model and evaluate on validation + test.

    Returns a dict with: model (the classifier), vectorizer, metrics
    (validation + test), meta, and the evaluation report text.
    """
    classifier, vectorizer = build_tfidf_pipeline(
        max_features=max_features, class_weight=class_weight
    )
    fit_model(train_records, vectorizer, classifier)

    # Evaluate validation
    val_X, val_y = split_features_labels(validation_records, vectorizer)
    val_pred = classifier.predict(val_X)
    val_metrics = ev.evaluate_predictions(val_y, val_pred)

    # Evaluate test (final, reported)
    test_X, test_y = split_features_labels(test_records, vectorizer)
    test_pred = classifier.predict(test_X)
    test_metrics = ev.evaluate_predictions(test_y, test_pred)

    meta = {
        "model_name": MODEL_NAME,
        "task": "binary scam/safe message classification",
        "classifier": type(classifier).__name__,
        "feature_representation": "tfidf word 1-2 grams + char 3-5 grams",
        "preprocessing": "unicode_nfc + latin_fold + url_anonymize + ws_norm",
        "class_weight": class_weight,
        "random_state": RANDOM_STATE,
        "n_train": len(train_records),
        "n_validation": len(validation_records),
        "n_test": len(test_records),
        "trained_at": ev.timestamp_iso(),
    }

    bundle = {
        "vectorizer": vectorizer,
        "classifier": classifier,
        "meta": meta,
    }

    train_distribution = dict(Counter(r["label"] for r in train_records))
    val_distribution = dict(Counter(r["label"] for r in validation_records))
    test_distribution = dict(Counter(r["label"] for r in test_records))

    metrics = {
        "meta": meta,
        "class_distribution": {
            "train": train_distribution,
            "validation": val_distribution,
            "test": test_distribution,
        },
        "validation": val_metrics,
        "test": test_metrics,
    }

    report_text = (
        "# ScamShield ML Evaluation Report\n\n"
        + ev.build_human_report(
            "Validation set", val_metrics, model_name=MODEL_NAME,
            n_train=len(train_records), n_validation=len(validation_records),
            n_test=len(test_records),
            train_distribution=train_distribution,
        )
        + "\n\n"
        + ev.build_human_report(
            "Test set (frozen held-out)", test_metrics, model_name=MODEL_NAME,
            n_train=len(train_records), n_validation=len(validation_records),
            n_test=len(test_records),
            train_distribution=train_distribution,
        )
    )

    if save_artifacts:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        import joblib

        joblib.dump(bundle, out / MODEL_FILENAME)
        ev.write_metrics(metrics, out_dir=out, path="metrics.json")
        ev.write_report(report_text, out_dir=out, path="evaluation_report.md")

    return {
        "model": classifier,
        "vectorizer": vectorizer,
        "meta": meta,
        "metrics": metrics,
        "report_text": report_text,
        "bundle": bundle,
    }


def main(argv=None):
    import sys

    parser = argparse.ArgumentParser(description="Train the ScamShield ML model")
    parser.add_argument(
        "--data-root", default=str(DEFAULT_DATA_ROOT),
        help="Root directory holding train/validation/test/messages.csv",
    )
    parser.add_argument(
        "--output-dir", default=str(DEFAULT_OUTPUT_DIR),
        help="Where to write model + metrics (default: models)",
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Train and evaluate in memory without writing artifacts",
    )
    parser.add_argument(
        "--max-features", type=int, default=None,
        help="Optional cap on TF-IDF vocabulary size (default: unbounded-ish)",
    )
    parser.add_argument(
        "--class-weight", default="balanced",
        choices=["balanced", "none"],
        help="Logistic Regression class_weight; 'none' disables balancing",
    )
    args = parser.parse_args(argv)

    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover
        pass

    try:
        loaded = ds.load_all(args.data_root)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[train] ERROR: {exc}")
        return 1

    train = loaded["train"]
    validation = loaded["validation"]
    test = loaded["test"]
    leakage = loaded["leakage"]
    distribution = loaded["distribution"]

    print("[train] Loaded splits (after schema validation + dedupe):")
    for split, rows in (("train", train), ("validation", validation),
                        ("test", test)):
        print(f"  {split:10s} n={len(rows)} {dict(Counter(r['label'] for r in rows))}")
    if leakage["leakage_detected"]:
        print(
            f"[train] WARNING: {leakage['total_leaked_texts']} distinct text(s) "
            "appear in more than one split (leakage detected - reported, not "
            "silenced)."
        )

    class_weight = None if args.class_weight == "none" else "balanced"
    start = time.time()
    result = train_and_evaluate(
        train, validation, test,
        output_dir=args.output_dir,
        save_artifacts=not args.no_save,
        max_features=args.max_features,
        class_weight=class_weight,
    )
    elapsed = time.time() - start

    print("\n[train] ---------- VALIDATION ----------")
    print(json.dumps(result["metrics"]["validation"], indent=2))
    print("\n[train] ---------- TEST (frozen) ----------")
    print(json.dumps(result["metrics"]["test"], indent=2))
    print(f"\n[train] Finished in {elapsed:.2f}s.")

    if not args.no_save:
        out = Path(args.output_dir)
        print(
            f"\n[train] Artifacts written to {out.resolve()}: "
            f"{MODEL_FILENAME}, metrics.json, evaluation_report.md"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
