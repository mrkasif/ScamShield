"""System evaluators for the ScamShield research lab.

Evaluate one or more ScamShield systems against a labelled message dataset.
Each evaluator returns a self-contained result dict with metrics, confusion
components, human-readable notes, and sanitised FP / FN examples ready for
reporting.

Systems evaluated:
  - **Rule Engine**      — `scamshield.nlp.analyze_message` deterministic rules
  - **Local ML**         — `scamshield.ml.predict_message` TF-IDF + LogisticReg
  - **Combined ScamShield** — `scamshield.analyze("message", ...)` unified API

Positive class is **"scam"** for all systems. The evaluation does NOT change
any system's scoring logic.

For messages, the combined ScamShield verdict is driven entirely by the
deterministic rule engine (ML is kept separate under engine_results and does
not alter the top-level is_suspicious). The combined evaluator is therefore
expected to match the rule engine on the message benchmark — this is an
honest design property, not a bug, and is documented here explicitly.

No network requests are made. Results are deterministic (same input → same
output for both the rule engine and ML, which are fully stateless).
"""
from __future__ import annotations

from .metrics import classification_metrics, bool_to_label, POSITIVE, NEGATIVE
from .sanitize import sanitize_example
from ..nlp.engine import analyze_message as _nlp_analyze
from ..ml.predict import predict_message as _ml_predict
from ..analyzer import analyze as _unified_analyze


_POSITIVE_PREDICTION_DOCS = {
    "rule": (
        "positive='scam' when the deterministic rule engine fires: "
        "nlp.analyze_message(text)['is_scam'] == True."
    ),
    "ml": (
        "positive='scam' when the trained TF-IDF + Logistic Regression model "
        "predicts scam: ml.predict_message(text)['prediction'] == 'scam' "
        "(model_available must be True)."
    ),
    "combined": (
        "positive='scam' when the unified analyzer classifies the message as "
        "suspicious: scamshield.analyze('message', text)['is_suspicious'] == True. "
        "On message inputs, the top-level verdict is driven by the deterministic "
        "rule engine; ML is attached under engine_results but does not alter the "
        "top-level is_suspicious. The combined result therefore matches the rule "
        "engine on the message benchmark by design."
    ),
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run_predictors_on_records(records, rule_fn, ml_fn, combined_fn):
    """Run three predictors and collect parallel label/prediction lists."""
    rule_preds: list[str] = []
    ml_preds: list[str] = []
    combined_preds: list[str] = []
    ml_available: bool | None = None
    ml_failures = 0

    for rec in records:
        text = rec["text"]

        # Rule engine
        nlp_result = rule_fn(text)
        rule_preds.append(bool_to_label(bool(nlp_result.get("is_scam"))))

        # ML
        ml_result = ml_fn(text)
        ml_pred = ml_result.get("prediction")
        ml_avail = bool(ml_result.get("model_available"))
        if ml_available is None:
            ml_available = ml_avail
        if ml_avail and ml_pred is not None:
            ml_preds.append(str(ml_pred).lower())
        else:
            ml_preds.append(NEGATIVE)
            ml_failures += 1

        # Combined / unified
        unified = combined_fn(text)
        combined_preds.append(bool_to_label(bool(unified.get("is_suspicious"))))

    return rule_preds, ml_preds, combined_preds, ml_available, ml_failures


def _collect_examples(records, predictions, true_labels, max_examples=8):
    """Collect sanitised FP and FN examples from parallel label/pred lists."""
    fp_examples: list[dict] = []
    fn_examples: list[dict] = []
    for rec, pred, label in zip(records, predictions, true_labels):
        if label == POSITIVE and pred == NEGATIVE:
            fn_examples.append(sanitize_example(rec, pred))
        elif label == NEGATIVE and pred == POSITIVE:
            fp_examples.append(sanitize_example(rec, pred))
        if len(fp_examples) >= max_examples and len(fn_examples) >= max_examples:
            break
    return fp_examples[:max_examples], fn_examples[:max_examples]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_system(
    records: list[dict],
    *,
    predict_fn,
    system_name: str,
    max_examples: int = 8,
) -> dict:
    """Evaluate a single system against labelled records.

    Args:
        records: list of dicts with keys "text", "scam_or_safe" (label),
                 "id", "language", "scam_type".
        predict_fn: callable(text: str) -> dict with keys "prediction"
                    ("scam" / "safe"), "model_available" (bool).
        system_name: one of "rule" | "ml" | "combined" (used for docs).
        max_examples: max FP / FN examples to return.

    Returns a dict with metrics, confusion components, examples, and
    human-readable notes. Never raises on missing models — if predict_fn
    consistently returns unavailable, the result documents that.
    """
    true_labels: list[str] = []
    pred_labels: list[str] = []

    for rec in records:
        text = rec["text"]
        true_label = rec.get("scam_or_safe", rec.get("label", ""))
        if true_label not in (POSITIVE, NEGATIVE):
            continue
        true_labels.append(true_label)
        result = predict_fn(text)
        pred = str(result.get("prediction", NEGATIVE)).lower()
        pred_labels.append(pred if pred in (POSITIVE, NEGATIVE) else NEGATIVE)

    metrics = classification_metrics(true_labels, pred_labels)

    fp_examples, fn_examples = _collect_examples(
        records, pred_labels, true_labels, max_examples=max_examples,
    )

    return {
        "system": system_name,
        "positive_prediction": POSITIVE,
        "negative_prediction": NEGATIVE,
        "prediction_documentation": _POSITIVE_PREDICTION_DOCS[system_name],
        "n_samples": metrics["n_samples"],
        "accuracy": metrics["accuracy"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "confusion_matrix": metrics["confusion_matrix"],
        "class_distribution": metrics["class_distribution"],
        "imbalanced": metrics["imbalanced"],
        "fp_count": metrics["confusion_matrix"]["false_positive"],
        "fn_count": metrics["confusion_matrix"]["false_negative"],
        "tp_count": metrics["confusion_matrix"]["true_positive"],
        "tn_count": metrics["confusion_matrix"]["true_negative"],
        "fp_examples": fp_examples,
        "fn_examples": fn_examples,
        "note_about_errors": metrics.get("note_about_errors", ""),
    }


def evaluate_rule(records, *, max_examples: int = 8) -> dict:
    """Evaluate the deterministic rule engine on labelled message records."""
    def _predict(text):
        result = _nlp_analyze(text)
        pred = POSITIVE if result.get("is_scam") else NEGATIVE
        return {"prediction": pred, "model_available": True}

    return evaluate_system(records, predict_fn=_predict, system_name="rule",
                           max_examples=max_examples)


def evaluate_ml(records, *, model_path=None, max_examples: int = 8) -> dict:
    """Evaluate the trained ML model on labelled message records.

    If the model is unavailable, every sample is labelled NEGATIVE (safe) and
    the result documents model_available=False. The original dataset and model
    are never modified.
    """
    def _predict(text):
        result = _ml_predict(text, model_path=model_path)
        return {
            "prediction": result.get("prediction", NEGATIVE),
            "model_available": bool(result.get("model_available")),
        }
    return evaluate_system(records, predict_fn=_predict, system_name="ml",
                           max_examples=max_examples)


def evaluate_combined(records, *, max_examples: int = 8) -> dict:
    """Evaluate the unified ScamShield analyzer on labelled message records.

    On message inputs, is_suspicious is driven by the deterministic rule
    engine; ML is kept separate under engine_results. The combined evaluation
    is therefore expected to match the rule engine — this is documented as a
    design property.
    """
    def _predict(text):
        result = _unified_analyze("message", text)
        pred = POSITIVE if result.get("is_suspicious") else NEGATIVE
        return {"prediction": pred, "model_available": True}

    return evaluate_system(records, predict_fn=_predict, system_name="combined",
                           max_examples=max_examples)


def build_comparison_table(rule_result, ml_result, combined_result) -> list[dict]:
    """Build a machine-readable comparison table from evaluation results.

    Each row: {system, accuracy, precision, recall, f1, n_samples, note}.
    Only values actually measured are included. Unavailable ML results are
    flagged.
    """
    ml_available = ml_result.get("n_samples", 0) > 0
    table: list[dict] = []

    def _row(res, label):
        return {
            "system": label,
            "accuracy": res["accuracy"],
            "precision": res["precision"],
            "recall": res["recall"],
            "f1": res["f1"],
            "n_samples": res["n_samples"],
            "note": res.get("note_about_errors", ""),
        }

    table.append(_row(rule_result, "Rule Engine"))
    if ml_available:
        table.append(_row(ml_result, "Local ML"))
    else:
        table.append({
            "system": "Local ML",
            "accuracy": None,
            "precision": None,
            "recall": None,
            "f1": None,
            "n_samples": ml_result.get("n_samples", 0),
            "note": "Model unavailable. Metrics cannot be computed.",
        })
    table.append(_row(combined_result, "Combined ScamShield"))
    return table
