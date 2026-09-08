"""Prediction API for the ScamShield ML layer.

`predict_message()` is the framework-independent entry point a UI/API (and the
unified analyzer) calls. It returns a JSON-serializable dict and NEVER crashes
if the model has not been trained yet - instead it returns a structured
"ML model unavailable" result.

Importantly:
  * if Logistic Regression probabilities are used, they are exposed as the
    model's own predicted-class probability and labelled
    `confidence_type="model_probability"` with an explicit caveat that it is
    not a calibrated, safety-certified probability;
  * the raw score is a 0-100 integer derived from that probability (or from a
    bounded transformation of a decision score where applicable);
  * model files are loaded with joblib and the resulting artifact is
    structure-checked (it must be a dict bundle exposing `vectorizer` and
    `classifier`). The model file is treated as a local, untrusted artifact and
    is never fetched from anywhere.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

def _default_model_path() -> Path:
    """Repository-root-relative default model path.

    Resolved from this file's location so loading works regardless of the
    current working directory (Linux servers, WSGI hosts, test runners).
    """
    return Path(__file__).resolve().parents[3] / "models" / "scamshield_tfidf.joblib"


_DEFAULT_MODEL_PATH = _default_model_path()

UNAVAILABLE = {
    "success": True,
    "model_available": False,
    "prediction": None,
    "score": None,
    "confidence": None,
    "confidence_type": "unavailable",
    "model": None,
    "features_used": None,
    "warning": "ML model unavailable - no trained model was found. Run "
               "`python -m src.scamshield.ml.train` to train one. "
               "The deterministic message engine is used instead.",
}


def _resolve_model_path(path=None) -> Path:
    return Path(path) if path is not None else _DEFAULT_MODEL_PATH


def load_model(path=None):
    """Load the persisted {vectorizer, classifier, meta} bundle.

    Returns a dict with keys: vectorizer, classifier, meta (dict of model
    metadata) or None if the file is absent.

    Raises RuntimeError if the artifact exists but cannot be trusted/parsed.
    """
    model_path = _resolve_model_path(path)
    if not model_path.exists():
        return None
    try:
        bundle = joblib.load(model_path)
    except Exception as exc:
        raise RuntimeError(
            f"Could not load ML model from {model_path}: {exc}"
        ) from exc
    if not isinstance(bundle, dict):
        raise RuntimeError(
            "ML model artifact is not a dict bundle; refusing to use it."
        )
    required = {"vectorizer", "classifier"}
    missing = required - set(bundle)
    if missing:
        raise RuntimeError(
            f"ML model artifact is missing key(s): {sorted(missing)}; "
            "refusing to use it."
        )
    return bundle


def _open_model_bundle(path=None):
    try:
        bundle = load_model(path)
    except Exception as exc:
        # A present-but-corrupt/untrusted artifact is treated as unavailable so
        # prediction never crashes - but the reason is surfaced in the warning.
        return {"__error__": str(exc)}
    if bundle is None:
        return None
    return bundle


def _prob_to_score(probability: float) -> int:
    """Map a scam-probability in [0,1] to a 0-100 integer score."""
    return max(0, min(100, int(round(probability * 100))))


def _predict_bundle(bundle, text: str) -> dict:
    from .preprocessing import preprocess

    cleaned = preprocess(text)
    if not cleaned:
        return {
            "success": True,
            "model_available": True,
            "prediction": "safe",
            "score": 0,
            "confidence": 0.0,
            "confidence_type": "model_probability",
            "model": bundle.get("meta", {}).get("model_name", "unknown"),
            "features_used": "tfidf_word_char_ngrams",
            "warning": "Empty message after preprocessing; predicted safe with "
                       "no evidence.",
        }

    vectorizer = bundle["vectorizer"]
    classifier = bundle["classifier"]

    try:
        vector = vectorizer.transform([cleaned])
        label = str(classifier.predict(vector)[0])
        if hasattr(classifier, "predict_proba"):
            # Logistic Regression exposes a genuine probability of class
            # membership. We report the probability of the predicted class.
            proba = classifier.predict_proba(vector)[0]
            classes = [str(c) for c in classifier.classes_]
            idx = classes.index(label) if label in classes else 0
            prob = float(proba[idx])
            confidence_type = "model_probability"
            score_int = _prob_to_score(prob)
            confidence = round(prob * 100, 1)
            warning = None
        else:
            # Linear SVM decision scores are NOT probabilities. Normalise the
            # signed decision score to a bounded 0-1 "pseudo-value" and label
            # it explicitly as such; we never call it a probability.
            decision = float(classifier.decision_function(vector)[0])
            pseudo = _decision_to_prob(decision)
            confidence_type = "normalized_decision_score"
            score_int = _prob_to_score(pseudo)
            confidence = round(pseudo * 100, 1)
            warning = (
                "Normalized decision score - NOT a calibrated probability."
            )
        return {
            "success": True,
            "model_available": True,
            "prediction": label,
            "score": score_int,
            "confidence": confidence,
            "confidence_type": confidence_type,
            "model": bundle.get("meta", {}).get("model_name", "unknown"),
            "features_used": "tfidf_word_char_ngrams",
            "warning": warning,
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"ML prediction failed: {exc}",
            "error_type": "engine_error",
            "model_available": True,
            "prediction": None,
            "score": None,
            "confidence": None,
            "confidence_type": "error",
            "model": bundle.get("meta", {}).get("model_name", "unknown"),
            "features_used": "tfidf_word_char_ngrams",
            "warning": None,
        }


def _sig(x: float) -> float:
    """Sigmoid used only for normalized decision-score display."""
    import math

    return 1.0 / (1.0 + math.exp(-x))


def _decision_to_prob(score: float) -> float:
    """Map a signed linear decision score to a 0-1 "pseudo-probability".

    Used only when a classifier has no predict_proba (e.g. LinearSVC). The
    result is a bounded monotonic transform of the decision score, labelled as
    a NORMALIZED decision score - explicitly not a calibrated probability.
    """
    return _sig(score)  # 0 when very negative, ~0.5 at 0, 1 when large positive


def predict_message(text, model_path=None) -> dict:
    """Classify a single message with the trained local ML model.

    Args:
        text: the raw message string.
        model_path: optional override path to the persisted model bundle.

    Returns a JSON-serializable dict. If the model is missing this returns an
    "ML model unavailable" dict (success=True, model_available=False) instead
    of raising, so callers can fall back to the deterministic engine.
    """
    if text is None:
        text = ""
    if not isinstance(text, str):
        raise TypeError(f"predict_message() expects str, got {type(text).__name__}")

    bundle = _open_model_bundle(model_path)
    if bundle is None:
        return dict(UNAVAILABLE)
    if isinstance(bundle, dict) and "__error__" in bundle:
        result = dict(UNAVAILABLE)
        result["warning"] = (
            "ML model unavailable - the model file could not be loaded: "
            f"{bundle['__error__']}. Run `python -m src.scamshield.ml.train` "
            "to retrain. The deterministic message engine is used instead."
        )
        return result

    result = _predict_bundle(bundle, text)
    result.setdefault("warning", None)
    return result


def predict_messages(texts, model_path=None) -> list[dict]:
    """Predict several messages, returning a list of per-message results."""
    return [predict_message(t, model_path=model_path) for t in texts]


# ---------------------------------------------------------------------------
# Serialization helpers (framework-independent JSON contract)
# ---------------------------------------------------------------------------

def to_json(result: dict) -> str:
    """Encode an ML result dict as JSON (utf-8, non-strict of floats)."""
    return json.dumps(result, ensure_ascii=False, indent=2)
