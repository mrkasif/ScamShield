"""ScamShield message analysis engine.

Public entry point:
    analyze_message(text: str) -> dict

Combines detectors -> scoring -> category -> explainability -> recommendations
into a single structured result. Deterministic (same input -> same output), no
network, no ML model required.

When the message contains URLs they are also analysed with the local, static
URL intelligence engine (src/scamshield/url) and the results are added under
"url_analysis" and "combined_risk". This never changes the existing message
fields - the message scanner behaves exactly as before.
"""

from __future__ import annotations

from . import detectors
from . import scoring
from . import category
from . import explain
from ..url.scoring import combine_message_and_urls
from ..url.engine import analyze_url


def analyze_message(text: str) -> dict:
    """Analyze a user-supplied message and return a structured result.

    The result contains: is_scam, risk_score, risk_level, scam_type,
    confidence, detected_indicators, explanations, recommendations,
    detected_urls, plus url_analysis (per-URL static URL risk assessments) and
    combined_risk (message + strongest URL signal).
    """
    text = text or ""

    # 1) Run all detectors
    detections = detectors.detect_all(text)
    severities = {name: d["severity"] for name, d in detections.items()}

    # 2) Extract URLs (identification only)
    urls = detectors.extract_urls(text)

    # 3) Weighted risk scoring
    scored = scoring.compute_score(detections, text)
    fired = scored["fired_indicators"]

    # 4) Category from strongest evidence
    scam_type = category.predict_category(
        detections, scored["is_scam"], fired
    )

    # 5) Explainability
    explanations = explain.build_explanations(fired, severities)

    # 6) Recommendations
    recommendations = explain.build_recommendations(
        "safe" if not scored["is_scam"] else scam_type
    )

    # 7) Optional static URL analysis (never fetches the URL)
    url_analysis = [analyze_url(u) for u in urls]
    combined_risk = combine_message_and_urls(
        scored["risk_score"], [a["risk_score"] for a in url_analysis]
    )

    return {
        "is_scam": scored["is_scam"],
        "risk_score": scored["risk_score"],
        "risk_level": scored["risk_level"],
        "scam_type": scam_type,
        "confidence": scored["confidence"],
        "detected_indicators": fired,
        "detected_urls": urls,
        "explanations": explanations,
        "recommendations": recommendations,
        "url_analysis": url_analysis,
        "combined_risk": combined_risk,
    }
