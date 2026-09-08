"""ScamShield URL scanning command-line demo.

Run interactively:
    python -m app.url_scan

Or pass URLs as arguments (static analysis only - the link is never opened):
    python -m app.url_scan "https://secure-sbi-verify.example.com/login"
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure the repo root and the src/ layout are importable.
_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from scamshield.url import analyze_url  # noqa: E402


def print_result(url: str) -> None:
    r = analyze_url(url)
    print("## SCAMSHIELD URL ANALYSIS")
    print()
    print(f"URL: {r['url']}")
    print(f"Risk Score: {r['risk_score']}/100")
    print(f"Risk Level: {r['risk_level']}")
    print(f"Suspicious: {'YES' if r['is_suspicious'] else 'NO'}")
    print(f"Confidence: {r['confidence']}%")
    print()
    print("Indicators:")
    if r["indicators"]:
        for ind in r["indicators"]:
            print(f"* {ind}")
    else:
        print("* (none)")
    print()
    p = r["parse"]
    print(f"Parsed: scheme={p['scheme'] or '-'} host={p['hostname'] or '-'}")
    print(f"        root_domain={p['root_domain'] or '-'} "
          f"subdomains={p['subdomains'] or '-'} tld={p['tld'] or '-'}")
    print()
    print("Why:")
    if r["explanation"]:
        for e in r["explanation"]:
            line = f"* [{e['severity']}] (+{e['score']:.0f}) {e['reason']}"
            if e.get("evidence"):
                line += f"  [evidence: {e['evidence']}]"
            print(line)
    else:
        print("* No risk indicators detected.")
    print()
    print("Recommended Actions:")
    for rec in r["recommendations"]:
        print(f"* {rec}")
    print()


def main(argv: list[str] | None = None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    if argv:
        for url in argv:
            print_result(url)
        return 0

    # Interactive loop
    print("ScamShield URL scanner - static analysis only (never opens links)")
    print("Type 'quit' or 'exit' to stop")
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