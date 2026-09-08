"""Evaluation + metrics persistence for the ScamShield ML layer.

Computes binary-classification metrics (accuracy, precision, recall, F1,
confusion matrix, sample count, class distribution) on an evaluation split,
signals whether the minority class is "scam" (class imbalance), and separately
quantifies the two error directions that matter for a security tool:

  * False negatives  : a scam message predicted safe (most dangerous - missed
                       threats)
  * False positives  : a safe message predicted scam (harms trust, user
                       friction)

Metrics are saved in machine-readable JSON and a human-readable Markdown
report. The persistence functions write under `models/`.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_OUTPUT_DIR = Path("models")


def evaluate_predictions(labels, predictions, classes=None) -> dict:
    """Compute metrics from list of true labels and predicted labels.

    `classes` may be a 2-tuple of (scam_label, safe_label). If not provided,
    "scam" is assumed to be the positive class (standard for this dataset).
    """
    if classes is None:
        scam_label, safe_label = "scam", "safe"
    else:
        scam_label, safe_label = classes

    n = len(labels)
    if n == 0:
        raise ValueError("Cannot evaluate empty predictions.")

    tp = fp = tn = fn = 0
    for true, pred in zip(labels, predictions):
        if true == scam_label and pred == scam_label:
            tp += 1
        elif true == scam_label and pred != scam_label:
            fn += 1
        elif true != scam_label and pred == scam_label:
            fp += 1
        else:
            tn += 1

    accuracy = (tp + tn) / n if n else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    from collections import Counter

    true_dist = dict(Counter(labels))

    return {
        "positive_class": scam_label,
        "negative_class": safe_label,
        "n_samples": n,
        "confusion_matrix": {
            "true_positive": tp,
            "false_negative": fn,
            "false_positive": fp,
            "true_negative": tn,
        },
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "class_distribution": true_dist,
        "imbalanced": (len(true_dist) >= 1 and
                       min(true_dist.values()) != max(true_dist.values())),
        "note_about_errors": (
            "False negatives = scam predicted as safe (missed threats - "
            "the higher-risk error for users). False positives = safe "
            "predicted as scam (harms trust / causes friction)."
        ),
    }


def summarize_prediction_counts(results: list[dict]) -> dict:
    """Count model_available / success / prediction values across results."""
    counts = {"total": len(results), "model_available": 0, "failures": 0}
    pred_counts = {}
    for r in results:
        if r.get("model_available"):
            counts["model_available"] += 1
        if not r.get("success"):
            counts["failures"] += 1
        p = r.get("prediction")
        pred_counts[p] = pred_counts.get(p, 0) + 1
    counts["predictions"] = pred_counts
    return counts


def write_metrics(metrics: dict, out_dir=DEFAULT_OUTPUT_DIR,
                  path="metrics.json") -> Path:
    """Persist metrics as machine-readable JSON (nested dicts are fine)."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / path
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(metrics, handle, ensure_ascii=False, indent=2, default=str)
    return out_path


def write_report(report_text: str, out_dir=DEFAULT_OUTPUT_DIR,
                 path="evaluation_report.md") -> Path:
    """Persist a human-readable Markdown evaluation report."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / path
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write(report_text)
    return out_path


def build_human_report(
    section_label: str,
    metrics: dict,
    *,
    model_name: str = "",
    n_train: int = 0,
    n_validation: int = 0,
    n_test: int = 0,
    train_distribution: dict | None = None,
    leakage: dict | None = None,
) -> str:
    """Build a Markdown report for one evaluation split."""
    lines = [
        f"## {section_label}",
        "",
    ]
    if model_name:
        lines.append(f"- **Model**: {model_name}")
    lines.append(
        f"- **Samples (n)**: {metrics.get('n_samples')} "
        f"(train={n_train}, validation={n_validation}, test={n_test})"
    )
    lines.append(f"- **Class distribution**: {metrics.get('class_distribution')}")
    if train_distribution is not None:
        lines.append(f"- **Training class distribution**: {train_distribution}")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    for key in ("accuracy", "precision", "recall", "f1"):
        lines.append(f"| {key} | {metrics.get(key)} |")
    cm = metrics.get("confusion_matrix", {})
    lines.append("")
    lines.append("### Confusion matrix (positive='scam')")
    lines.append("")
    lines.append("| | Predicted scam | Predicted safe |")
    lines.append("|---|---|---|")
    lines.append(f"| Actual scam | {cm.get('true_positive', 0)} "
                 f"(TP) | {cm.get('false_negative', 0)} (FN) |")
    lines.append(f"| Actual safe | {cm.get('false_positive', 0)} "
                 f"(FP) | {cm.get('true_negative', 0)} (TN) |")
    lines.append("")
    lines.append(f"- **False negatives (missed scams)**: {cm.get('false_negative', 0)}")
    lines.append(f"- **False positives (safe flagged)**: {cm.get('false_positive', 0)}")
    lines.append("")
    lines.append(f"> {metrics.get('note_about_errors', '')}")
    if metrics.get("imbalanced"):
        lines.append(
            "> Note: the dataset is class-imbalanced (safe vs scam counts "
            "differ). Accuracy alone is misleading; precision/recall/F1 and "
            "the confusion matrix are the reported headline."
        )
    if leakage and leakage.get("leakage_detected"):
        lines.append("")
        lines.append("### Data leakage warning")
        lines.append("")
        lines.append(
            f"- **{leakage.get('total_leaked_texts', 0)}** distinct message "
            "text(s) appear in more than one split. This can inflate "
            "evaluation scores and is reported rather than hidden. See "
            "`src/scamshield/ml/README.md` for implications."
        )
    return "\n".join(lines) + "\n"


def timestamp_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
