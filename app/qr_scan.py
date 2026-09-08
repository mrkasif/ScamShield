"""ScamShield QR scanning command-line demo.

Local, offline QR analysis (the decoded URL is never opened, the UPI payload
is never executed):

    python -m app.qr_scan "path/to/qr.png"
    python -m app.qr_scan "upc.png" "restaurant.jpg" "qrcode.webp"

Interactive-only mode has no image; use app.scan / app.url_scan instead.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root and the src/ layout are importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield.qr import analyze_qr  # noqa: E402


def _print_explanation(entries) -> None:
    if not entries:
        print("* No risk indicators detected.")
        return
    for entry in entries:
        line = (
            f"* [{entry['severity']}] (+{entry['score']:.0f}) {entry['reason']}"
        )
        if entry.get("evidence"):
            line += f"  [evidence: {entry['evidence']}]"
        print(line)


def print_result(path: str) -> None:
    r = analyze_qr(path)
    print("## SCAMSHIELD QR ANALYSIS")
    print()
    print(f"File: {r['file']}")
    print(f"Status: {r['status']}")
    print(f"Content Type: {r['content_type'].upper()}")
    print(f"Risk Score: {r['risk_score']}/100")
    print(f"Risk Level: {r['risk_level']}")
    print(f"Suspicious: {'YES' if r['is_suspicious'] else 'NO'}")
    print(f"Confidence: {r['confidence']}%")
    if r.get("multiple_codes"):
        print(f"QR Codes: {r['decoded_count']}")
    print()

    if r.get("decoded_content") is not None:
        print(f"Decoded Content: {r['decoded_content']}")
        print()
        print("Decoded Payloads:")
        for code in r.get("codes") or []:
            print(f"* {code}")
        print()

    print("Indicators:")
    if r["indicators"]:
        for ind in r["indicators"]:
            print(f"* {ind}")
    else:
        print("* (none)")
    print()

    print("Why:")
    _print_explanation(r["explanation"])
    print()

    # Per-code sections
    if r.get("multiple_codes"):
        for index, analysis in enumerate(r.get("code_analyses") or [], start=1):
            print(f"## QR CODE #{index}")
            print(f"Content Type: {analysis['content_type'].upper()}")
            print(f"Risk: {analysis['risk_score']}/100 {analysis['risk_level']}")
            if analysis.get("decoded_content") is not None:
                print(f"Payload: {analysis['decoded_content']}")
            print()

    if r.get("url_analysis"):
        u = r["url_analysis"]
        print("URL ANALYSIS (inherited from the URL Intelligence Engine)")
        print(f"* URL: {u['url']}")
        print(f"* Risk: {u['risk_score']}/100 {u['risk_level']}")
        p = u.get("parse", {})
        print(f"* Domain: {p.get('root_domain') or '-'} "
              f"(host: {p.get('hostname') or '-'}, TLD: {p.get('tld') or '-'})")
        print(f"* Indicators: {', '.join(u['indicators']) or '(none)'}")
        print()

    if r.get("upi_analysis"):
        u = r["upi_analysis"]
        up = u.get("parse", {})
        print("PAYMENT DESTINATION")
        print(f"* Payee Name: {up.get('payee_name') or '-'}")
        print(f"* UPI ID: {up.get('payee_address') or '-'}")
        print(f"* Amount: {up.get('amount') or '-'}")
        print(f"* Currency: {up.get('currency') or '-'}")
        print(f"* Transaction Note: {up.get('transaction_note') or '-'}")
        print(f"* Merchant Code: {up.get('merchant_code') or '-'}")
        print()

    if r.get("message_analysis"):
        m = r["message_analysis"]
        print("MESSAGE ANALYSIS (inherited from the message engine)")
        print(f"* Classification: {m.get('scam_type', '-')}")
        print(f"* Indicators: {', '.join(m.get('detected_indicators', [])) or '(none)'}")
        print()

    print("Recommended Actions:")
    for rec in r["recommendations"]:
        print(f"* {rec}")
    print()
    print("ScamShield performs local, static analysis only: it never opens the "
          "decoded URL and never executes the decoded payment.")
    print("-" * 60)
    print()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):  # pragma: no cover - non-text stdout
        pass
    if not argv:
        print("Usage: python -m app.qr_scan <image1.png> [image2.png ...]")
        print("Scans QR code images locally (no network, nothing is executed).")
        return 1
    for path in argv:
        print_result(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())