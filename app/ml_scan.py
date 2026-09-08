"""ScamShield local ML scanner - command-line demo.

Classify one message with the trained local ML model (TF-IDF + Logistic
Regression). Displays prediction, ML score (0-100), confidence, model name,
and whether the trained model is available.

    python -m app.ml_scan "Your account will be blocked. Verify KYC immediately..."
    python -m app.ml_scan --json "Your KYC has expired."

If the model has not been trained yet, it reports "ML model unavailable"
instead of crashing. Fully local - no network, no URL resolution, no external
API, and the text is never sent anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield.ml.predict import (
    predict_message,
    to_json,
)  # noqa: E402


def _bool_str(value) -> str:
    return "YES" if value else "NO"


def print_result(result: dict, *, as_json: bool = False) -> None:
    if as_json:
        print(to_json(result))
        return

    print("## SCAMSHIELD ML ANALYSIS")
    print()
    available = result.get("model_available", False)
    print(f"Model available  : {_bool_str(available)}")
    if not available:
        print(f"Prediction        : N/A")
        print(f"Score             : N/A")
        print(f"Confidence        : N/A")
        print()
        warning = result.get("warning") or "ML model unavailable."
        print(f"Note: {warning}")
        print()
        print("ScamShield ran fully locally (no network).")
        print("-" * 60)
        print()
        return

    print(f"Prediction        : {result.get('prediction', '-')}")
    score = result.get("score")
    print(f"ML score          : {'N/A' if score is None else f'{score}/100'}")
    conf = result.get("confidence")
    print(f"Confidence        : {'N/A' if conf is None else f'{conf}%'}")
    ctype = result.get("confidence_type", "-")
    print(f"Confidence type   : {ctype}")
    print(f"Model             : {result.get('model', '-')}")
    print(f"Features          : {result.get('features_used', '-')}")
    warning = result.get("warning")
    if warning and ctype == "normalized_decision_score":
        print()
        print(f"Note: {warning}")
    elif result.get("success") is False:
        print(f"Note: {result.get('error', 'prediction failed')}")
    if ctype == "model_probability":
        print()
        print("Note: confidence is the model's predicted-class probability - "
              "a heuristic estimate, not a calibrated, safety-certified "
              "probability.")
    print()
    print("ScamShield ran fully locally and deterministically (no network; "
          "the text was never sent anywhere).")
    print("-" * 60)
    print()


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-text stdout
        pass

    parser = argparse.ArgumentParser(description="ScamShield local ML scanner")
    parser.add_argument("message", nargs="?", default=None,
                        help="The message text to classify")
    parser.add_argument("--json", action="store_true",
                        help="print the raw JSON result")
    parser.add_argument("--model", default=None,
                        help="optional path to a model bundle (default: "
                             "models/scamshield_tfidf.joblib)")
    args = parser.parse_args(argv)

    if args.message is None:
        # Interactive prompt
        print("# SCAMSHIELD ML")
        print()
        while True:
            try:
                text = input("Message (or 'quit'): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0
            if text.lower() in {"quit", "exit", "q"}:
                return 0
            if not text:
                continue
            print_result(predict_message(text, model_path=args.model))
        return 0

    print_result(predict_message(args.message, model_path=args.model),
                 as_json=args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
