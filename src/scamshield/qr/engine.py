"""ScamShield QR security analysis - public entry point.

    analyze_qr(image_path) -> dict
    analyze_qr_content(text) -> dict

Both are fully local, deterministic and offline: no online QR APIs, no cloud
lookups, no keyed services. A decoded URL is analysed with the static URL
Intelligence Engine and decoded text with the static message engine - neither
ever fetches, opens or executes the destination.

When the image contains more than one QR code, every payload is analysed
independently and the final risk is combined with the documented 70% headroom
rule (strongest score wins; each weaker score adds 70% of its headroom):

    combined = strongest
    for each subsequent score s (sorted descending):
        combined = combined + (100 - combined) * (s / 100) * 0.7

Decoding is order-independent: identical inputs always produce identical
outputs and identical explanation ordering.
"""

from __future__ import annotations

from .content import classify_content
from .decode import decode_qr_codes
from .explain import build_recommendations, _unique
from .upi import analyze_upi
from ..nlp import analyze_message
from ..url import analyze_url

__all__ = ["analyze_qr", "analyze_qr_content", "combine_risk_scores"]


def _risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _context_entry(indicator: str, reason: str) -> dict:
    """QR-level context entry with a zero score (never changes the risk)."""
    return {
        "indicator": indicator,
        "severity": "low",
        "score": 0.0,
        "reason": reason,
        "evidence": "",
    }


def _normalize_message_entries(entries: list[dict]) -> list[dict]:
    """Turn message-engine explanations into the common QR schema."""
    out = []
    for entry in entries:
        out.append({
            "indicator": entry.get("indicator", "message_pattern"),
            "severity": entry.get("severity", "low"),
            "score": 0.0,
            "reason": entry.get("reason", "A message risk pattern was detected."),
            "evidence": "",
        })
    return out


def combine_risk_scores(scores: list[int | float]) -> float:
    """Combine several 0-100 scores with the documented 70% headroom rule.

    The result is always >= the strongest component (never a diluted average)
    and clamped to 0-100. Sorting desc makes the outcome order-independent.
    """
    cleaned = [float(s) for s in scores if s is not None] or [0.0]
    total = max(cleaned)
    for score in sorted(cleaned, reverse=True)[1:]:
        total = total + (100.0 - total) * (score / 100.0) * 0.7
    # Each step adds less than the remaining headroom, so total can never
    # overshoot 100 by more than float rounding - clamp it defensively.
    return min(100.0, max(0.0, total))


# ---------------------------------------------------------------------------
# Content analysis (decoded payload strings)
# ---------------------------------------------------------------------------

def analyze_qr_content(text: str) -> dict:
    """Analyze an already-decoded QR payload string.

    Content routing:
        url -> analyze_url (static URL Intelligence Engine)
        upi -> analyze_upi (static UPI scorer)
        text -> analyze_message (static message engine)
        unknown -> neutral result (never auto-malicious)

    Returned keys: success, status, content_type, decoded_content,
    risk_score, risk_level, is_suspicious, confidence, indicators,
    explanation [{indicator, severity, score, reason, evidence}],
    recommendations, url_analysis, message_analysis, upi_analysis, warning.
    """
    payload = (text or "").strip()
    content_type = classify_content(payload)

    if content_type == "url":
        url_analysis = analyze_url(payload)
        explanation = [
            _context_entry(
                "embedded_url_in_qr",
                "The QR code decodes to a URL. URL risk was inherited from "
                "the ScamShield URL Intelligence Engine.",
            )
        ]
        explanation.extend(list(url_analysis.get("explanation", [])))
        return {
            "success": True,
            "status": "DECODED",
            "content_type": content_type,
            "decoded_content": payload,
            "risk_score": url_analysis["risk_score"],
            "risk_level": url_analysis["risk_level"],
            "is_suspicious": url_analysis["is_suspicious"],
            "confidence": url_analysis["confidence"],
            "indicators": ["embedded_url_in_qr"]
            + list(url_analysis.get("indicators", [])),
            "explanation": explanation,
            "recommendations": build_recommendations(
                content_type, url_analysis["is_suspicious"], url_analysis=url_analysis
            ),
            "url_analysis": url_analysis,
            "message_analysis": None,
            "upi_analysis": None,
            "warning": "The decoded URL was analysed statically; it was never opened.",
        }

    if content_type == "upi":
        upi_analysis = analyze_upi(payload)
        explanation = [
            _context_entry("upi_payment_uri", "The QR code encodes a UPI payment URI.")
        ]
        explanation.extend(list(upi_analysis.get("explanation", [])))
        return {
            "success": True,
            "status": "DECODED",
            "content_type": content_type,
            "decoded_content": payload,
            "risk_score": upi_analysis["risk_score"],
            "risk_level": upi_analysis["risk_level"],
            "is_suspicious": upi_analysis["is_suspicious"],
            "confidence": upi_analysis["confidence"],
            "indicators": ["upi_payment_uri"]
            + list(upi_analysis.get("indicators", [])),
            "explanation": explanation,
            "recommendations": build_recommendations(
                content_type, upi_analysis["is_suspicious"], upi_analysis=upi_analysis
            ),
            "url_analysis": None,
            "message_analysis": None,
            "upi_analysis": upi_analysis,
            "warning": upi_analysis["warning"],
        }

    if content_type == "text":
        message_analysis = analyze_message(payload)
        explanation = [
            _context_entry(
                "embedded_text_in_qr",
                "The QR code decodes to text. Text risk was inherited from "
                "the ScamShield message engine.",
            )
        ]
        explanation.extend(
            _normalize_message_entries(message_analysis.get("explanations", []))
        )
        suspicious = message_analysis["risk_score"] >= 50
        detected = list(message_analysis.get("detected_indicators", []))
        return {
            "success": True,
            "status": "DECODED",
            "content_type": content_type,
            "decoded_content": payload,
            "risk_score": message_analysis["risk_score"],
            "risk_level": message_analysis["risk_level"],
            "is_suspicious": suspicious,
            "confidence": message_analysis["confidence"],
            "indicators": ["embedded_text_in_qr"] + detected,
            "explanation": explanation,
            "recommendations": build_recommendations(
                content_type, suspicious, message_analysis=message_analysis
            ),
            "url_analysis": message_analysis.get("url_analysis") or None,
            "message_analysis": message_analysis,
            "upi_analysis": None,
            "warning": "The decoded text was analysed locally by the message engine.",
        }

    # unknown content (or empty payload): neutral, never auto-malicious.
    return {
        "success": True,
        "status": "DECODED",
        "content_type": content_type,
        "decoded_content": payload,
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "confidence": 25,
        "indicators": [],
        "explanation": [
            _context_entry(
                "unrecognized_content",
                "The QR payload is not a URL, UPI URI or recognizable message, "
                "so it was not auto-classified as malicious.",
            )
        ],
        "recommendations": build_recommendations(content_type, False),
        "url_analysis": None,
        "message_analysis": None,
        "upi_analysis": None,
        "warning": "The QR payload type is not recognized; nothing was executed.",
    }


# ---------------------------------------------------------------------------
# Image analysis
# ---------------------------------------------------------------------------

def _base_image_result(file: str, error: str | None, note: str) -> dict:
    return {
        "success": True,
        "status": "NOT DECODED",
        "content_type": "unknown",
        "decoded_content": None,
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "confidence": 0,
        "indicators": [],
        "explanation": [_context_entry("no_qr_code_detected", note)],
        "recommendations": build_recommendations("none", False),
        "url_analysis": None,
        "message_analysis": None,
        "upi_analysis": None,
        "file": file,
        "decoded": False,
        "decoded_count": 0,
        "codes": [],
        "multiple_codes": False,
        "error": error,
        "note": note,
        "warning": None,
    }


def analyze_qr(image_path) -> dict:
    """Decode and analyse every QR code in an image file.

    Returned keys (a superset of analyze_qr_content):
        success, status ("DECODED" | "NOT DECODED" | "ERROR"), content_type,
        decoded_content (first code), risk_score, risk_level, is_suspicious,
        confidence, indicators, explanation, recommendations, url_analysis,
        message_analysis, upi_analysis, file, decoded, decoded_count, codes,
        multiple_codes, code_analyses, error, note, warning.

    The function never raises, never opens the decoded URLs and never
    executes decoded payloads.
    """
    file = str(image_path)
    decode_result = decode_qr_codes(image_path)
    if not decode_result["ok"]:
        note = decode_result.get("error") or "The image could not be decoded."
        return {
            **_base_image_result(file, decode_result.get("error"), note),
            "success": False,
            "status": "ERROR",
            "recommendations": [
                "ScamShield could not read the image. Use a clear, cropped "
                "photo of a single QR code and retry."
            ],
        }
    if not decode_result["codes"]:
        return _base_image_result(
            file, None, "No QR code was detected in the image."
        )

    analyses = [analyze_qr_content(code) for code in decode_result["codes"]]
    scores = [analysis["risk_score"] for analysis in analyses]
    combined = combine_risk_scores(scores)
    suspicious = combined >= 50

    primary = analyses[0]
    result = dict(primary)
    result.update({
        "status": "DECODED",
        "decoded": True,
        "decoded_count": len(analyses),
        "codes": list(decode_result["codes"]),
        "multiple_codes": len(analyses) > 1,
        "code_analyses": analyses,
        "file": file,
        "error": None,
        "note": None,
        "decoded_content": decode_result["codes"][0],
        "content_type": primary["content_type"],
        "risk_score": int(round(combined)),
        "risk_level": _risk_level(combined),
        "is_suspicious": suspicious,
        "confidence": max(a["confidence"] for a in analyses),
        "indicators": _unique(
            [ind for a in analyses for ind in a.get("indicators", [])]
        ),
    })

    explanation: list[dict] = []
    for index, analysis in enumerate(analyses):
        if index:
            explanation.append(
                _context_entry(
                    f"additional_qr_code_{index + 1}",
                    f"QR code #{index + 1} decodes to a {analysis['content_type']} "
                    "payload.",
                )
            )
        explanation.extend(analysis.get("explanation", []))
    if len(analyses) > 1:
        explanation.append(
            _context_entry(
                "multiple_qr_codes",
                "The image contains several QR codes; combined risk was computed "
                "with the documented 70% strongest+weaker rule "
                f"({result['risk_score']}/100).",
            )
        )
    explanation.sort(key=lambda entry: entry.get("score", 0.0), reverse=True)
    result["explanation"] = explanation

    recommendations = list(primary.get("recommendations", []))
    for index, analysis in enumerate(analyses[1:], start=2):
        if analysis.get("is_suspicious"):
            recommendations.append(
                f"QR code #{index} in the image is flagged suspicious - do not "
                "act on its content."
            )
    if len(analyses) > 1:
        recommendations.append(
            "The image contains several QR codes; a harmful second code can be "
            "hidden next to a legitimate one. Scan only the code you intended "
            "to scan."
        )
    result["recommendations"] = _unique(recommendations)

    result["warning"] = (
        "ScamShield decoded this image locally and analysed every payload "
        "statically. It never opened any URL and never executed any payment."
    )
    return result


__all__ = [
    "analyze_qr",
    "analyze_qr_content",
    "combine_risk_scores",
    "classify_content",
    "decode_qr_codes",
    "analyze_upi",
]