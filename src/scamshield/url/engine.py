"""ScamShield URL intelligence engine - public entry point.

    analyze_url(url: str) -> dict

Static, local, deterministic analysis of a URL string. The engine:
    * never opens the URL, resolves it, follows redirects or executes content;
    * never talks to a network service;
    * never crashes on malformed input.

The result is a *risk assessment* (0-100) with reasons, never a claim that a
URL is definitely malicious.
"""

from __future__ import annotations

from .parse import parse_url
from .indicators import detect_all
from .scoring import score_url, combine_message_and_urls
from .attachments import analyze_attachment_filename
from .sender import assess_sender
from . import explain


def analyze_url(url: str) -> dict:
    """Analyze a URL and return a structured risk assessment. Deterministic.

    Returned keys:
        url, parse, risk_score (0-100), risk_level, is_suspicious,
        confidence (0-100), indicators (list of names), explanation
        (list of {indicator, severity, score, reason}), recommendations.
    """
    parts = parse_url(url)
    findings = detect_all(parts)

    scored = score_url(findings)

    # Build a final explanation list: indicator contributions + combination
    # bonuses, each carrying its exact point contribution.
    explanation = list(scored["contributions"])
    for b in scored["bonuses"]:
        explanation.append(b)
    explanation.sort(key=lambda e: e.get("score", 0.0), reverse=True)

    recommendations = explain.build_recommendations(
        findings, scored["is_suspicious"]
    )

    return {
        "url": parts.get("raw") or url or "",
        "parse": {
            "scheme": parts.get("scheme") or "",
            "hostname": parts.get("hostname") or "",
            "root_domain": parts.get("root_domain") or "",
            "subdomains": parts.get("subdomains") or "",
            "tld": parts.get("tld") or "",
            "port": parts.get("port"),
            "username": parts.get("username"),
            "password": parts.get("password"),
            "path": parts.get("path") or "",
            "query": parts.get("query") or "",
            "fragment": parts.get("fragment") or "",
        },
        "risk_score": scored["risk_score"],
        "risk_level": scored["risk_level"],
        "is_suspicious": scored["is_suspicious"],
        "confidence": scored["confidence"],
        "indicators": sorted({f["indicator"] for f in findings}),
        "explanation": explanation,
        "recommendations": recommendations,
    }


__all__ = [
    "analyze_url",
    "combine_message_and_urls",
    "analyze_attachment_filename",
    "assess_sender",
    "parse_url",
    "score_url",
    "detect_all",
    "explain",
]