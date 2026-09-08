"""ScamShield unified analyzer command-line demo.

One consistent interface over the message, URL, QR and UPI engines:

    python -m app.analyze                              # interactive menu
    python -m app.analyze --type url --input "https://example.com"
    python -m app.analyze --type message --input "Your KYC has expired..."
    python -m app.analyze --type qr --input "tests/fixtures/qr/url_suspicious.png"
    python -m app.analyze --type upi --input "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR"

Add --json to print the raw unified result (JSON) instead of a readable report.

The existing `python -m app.scan`, `python -m app.url_scan` and
`python -m app.qr_scan` demos are untouched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ensure the repo root and the src/ layout are importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield import analyze  # noqa: E402

_MENU = [
    ("message", "Message"),
    ("url", "URL"),
    ("qr", "QR"),
    ("upi", "UPI URI"),
]


def _fmt_bool(value) -> str:
    return "YES" if value else "NO"


def print_result(unified: dict, *, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(unified, ensure_ascii=False, default=str))
        return

    print("## SCAMSHIELD UNIFIED ANALYSIS")
    print()
    print(f"Input Type: {unified.get('input_type', '-')}")
    print(f"Status: {unified.get('status', 'ANALYSED')}")
    if not unified.get("success"):
        print(f"ERROR: {unified.get('error', 'analysis failed')}")
        print(f"Error Type: {unified.get('error_type', '-')}")
        print()
        print("Recommendations:")
        for rec in unified.get("recommendations", []):
            print(f"* {rec}")
        print()
        print("ScamShield ran fully locally (no network).")
        print("-" * 60)
        print()
        return

    print(f"Risk Score: {unified['risk_score']}/100")
    print(f"Risk Level: {unified['risk_level']}")
    print(f"Suspicious: {_fmt_bool(unified['is_suspicious'])}")
    print(f"Scam Type: {unified.get('scam_type', '-')}")
    print(f"Confidence: {unified['confidence']}% (heuristic - "
          "not a calibrated probability)")
    print()
    print(f"Summary: {unified['summary']}")
    print()
    print("Indicators:")
    if unified["indicators"]:
        for ind in unified["indicators"]:
            print(f"* {ind}")
    else:
        print("* (none)")
    print()
    print("Why:")
    for entry in unified["explanation"]:
        line = f"* [{entry['severity']}] (+{entry['score']:.0f}) {entry['reason']}"
        if entry.get("evidence"):
            line += f"  [evidence: {entry['evidence']}]"
        print(line)
    if not unified["explanation"]:
        print("* (no risk explanation)")
    print()
    print("Recommended Actions:")
    for rec in unified["recommendations"]:
        print(f"* {rec}")
    print()
    if unified.get("evidence"):
        print("Evidence:")
        for key, value in unified["evidence"].items():
            if isinstance(value, list):
                rendered = ", ".join(str(v) for v in value)
            elif isinstance(value, dict):
                rendered = json.dumps(value, ensure_ascii=False)
            else:
                rendered = str(value)
            print(f"* {key}: {rendered}")
        print()
    if unified.get("warnings"):
        print("Warnings:")
        for warning in unified["warnings"]:
            print(f"* {warning}")
        print()
    print("ScamShield ran fully locally and deterministically (no network; "
          "the URL was never opened and no payment was executed).")
    print("-" * 60)
    print()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-text stdout
        pass

    if argv:
        parser = argparse.ArgumentParser(description="ScamShield unified analyzer")
        parser.add_argument("--type", help="message | url | qr | upi")
        parser.add_argument("--input", help="content to analyse (image path for qr)")
        parser.add_argument("--json", action="store_true",
                            help="print the raw unified JSON result")
        args = parser.parse_args(argv)
        if not args.type or args.input is None:
            parser.error("both --type and --input are required outside menu mode")
        itype = args.type.strip().lower()
        print_result(analyze(itype, args.input), as_json=args.json)
        return 0

    # Interactive menu
    print("# SCAMSHIELD")
    print()
    for index, (_key, label) in enumerate(_MENU, start=1):
        print(f"{index}. {label}")
    print(f"{len(_MENU) + 1}. Exit")
    print()
    while True:
        selection = input("Selection: ").strip()
        if selection.lower() in {"exit", "quit", "q"} or selection == "5":
            print("Bye.")
            return 0
        try:
            choice = int(selection)
        except ValueError:
            print(f"Invalid selection: {selection!r}")
            continue
        if 1 <= choice <= len(_MENU):
            itype, label = _MENU[choice - 1]
            prompt = "Message text" if itype == "message" else (
                "URL" if itype == "url" else
                "UPI URI" if itype == "upi" else "QR image path")
            value = input(f"{label} ({prompt}): ").strip()
            if value:
                print_result(analyze(itype, value))
        else:
            print(f"Invalid selection: {selection}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())