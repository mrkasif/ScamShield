"""ScamShield Local ML Intelligence layer.

A lightweight, fully-local TF-IDF + linear classifier (Logistic Regression)
baseline for binary scam/safe message classification. It is an ADDITIONAL
intelligence layer - it does NOT replace the deterministic message engine
(src/scamshield/nlp) which remains the primary, explainable scanner.

Primary entry point:

    from scamshield.ml import predict_message
    result = predict_message("Your KYC has expired. Click the link now.")

If the model has not been trained yet, `predict_message` returns an
"ML model unavailable" result instead of raising.

Train once (from the repo root):

    python -m src.scamshield.ml.train

Modules:
    preprocessing.py  deterministic text preprocessing (en/hi/mr/hinglish)
    dataset.py        load/validate/hygiene (dedupe, leakage detection)
    train.py          training pipeline + artifact persistence + metrics
    evaluate.py       metrics (accuracy/precision/recall/F1/confusion) + reports
    predict.py        prediction API (predict_message), graceful no-model path
"""

from .predict import predict_message, predict_messages

__all__ = ["predict_message", "predict_messages"]
