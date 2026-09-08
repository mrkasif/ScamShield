"""ScamShield command-line demo.

Run interactively:
    python -m app.scan

Or pass messages as arguments:
    python -m app.scan "Your KYC has expired. Verify immediately at this link."
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root and the src/ layout are importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield.nlp import analyze_message  # noqa: E402


def _pct_label(v: str) -> str:
    return v.upper()


def print_result(text: str) -> None:
    r = analyze_message(text)
    print("## SCAMSHIELD ANALYSIS")
    print()
    print(f"Risk Score: {r['risk_score']}/100")
    print(f"Risk Level: {r['risk_level']}")
    print(f"Classification: {r['scam_type']}")
    print(f"Confidence: {r['confidence']}%")
    print()
    print("Why:")
    if r["explanations"]:
        for e in r["explanations"]:
            print(f"* [{e['severity']}] {e['reason']}")
    else:
        print("* No risk indicators detected.")
    print()
    print("Detected URLs:")
    if r["detected_urls"]:
        for u in r["detected_urls"]:
            print(f"* {u}")
    else:
        print("* (none)")
    if r["url_analysis"]:
        print()
        print("URL Analysis (static):")
        for ua in r["url_analysis"]:
            print(f"* {ua['url']} -> {ua['risk_score']}/100 {ua['risk_level']}"
                  f" suspicious={ua['is_suspicious']}")
        cr = r["combined_risk"]
        print(f"Combined message+URL risk: {cr['score']}/100 ({cr['level']})")
    print()
    print("Recommended Actions:")
    for rec in r["recommendations"]:
        print(f"* {rec}")
    print()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if argv:
        # Non-interactive: analyse each arg
        for msg in argv:
            print_result(msg)
        return 0

    # Interactive loop
    print("ScamShield message scanner (type 'quit' or 'exit' to stop)")
    print("-" * 50)
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        low = line.lower()
        if low in {"quit", "exit", "q"}:
            break
        print_result(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
