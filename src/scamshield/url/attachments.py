"""Attachment filename risk heuristics for the ScamShield engine.

METADATA-ONLY - the engine never opens, inspects, downloads or executes an
attachment. It only looks at the file name to flag extensions that are
commonly used to deliver malware or macro-based credential stealers.

This is an *architecture point*: the message scanner identifies URLs and the
URL engine scores them; attachment analysis is the natural next extension of
the same static pipeline and is exposed here so callers can already use it
without any network access.
"""

from __future__ import annotations

# High-risk extensions: executable / script payloads. If a message delivers
# one of these, treat it as a strong scam signal.
HIGH_RISK_EXTENSIONS: dict[str, float] = {
    ".exe": 60.0,
    ".scr": 60.0,
    ".bat": 60.0,
    ".cmd": 60.0,
    ".com": 60.0,
    ".msi": 60.0,
    ".js": 50.0,
}

# Moderate-risk extensions: archive / macro-enabled document files that are
# regularly weaponised but also used legitimately.
MODERATE_RISK_EXTENSIONS: dict[str, float] = {
    ".zip": 35.0,
    ".rar": 35.0,
    ".7z": 30.0,
    ".docm": 35.0,
    ".xlsm": 35.0,
}


def _extension(name: str) -> str:
    idx = (name or "").rfind(".")
    if idx == -1:
        return ""
    return name[idx:].lower()


def _level(score: float) -> str:
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def analyze_attachment_filename(filename: str) -> dict:
    """Assess a file name's extension risk. Never executes anything.

    Returns:
        filename        the trimmed input as given
        attachment_present  bool
        extension       the lower-cased extension ("" when none)
        risk_score      0-100
        risk_level      LOW / MEDIUM / HIGH
        is_suspicious   True when HIGH (>= 50)
        indicators      list of {indicator, severity, score, reason}
    """
    name = (filename or "").strip()
    if not name:
        return {
            "filename": "",
            "attachment_present": False,
            "extension": "",
            "risk_score": 0,
            "risk_level": "LOW",
            "is_suspicious": False,
            "indicators": [],
        }

    ext = _extension(name)
    if ext in HIGH_RISK_EXTENSIONS:
        score = HIGH_RISK_EXTENSIONS[ext]
        indicators = [{
            "indicator": "high_risk_attachment",
            "severity": "high",
            "score": score,
            "reason": (f"The file extension '{ext}' is commonly used for "
                       "executable or script payloads. Attachments with these "
                       "extensions are a primary malware delivery vector - do "
                       "not open them from unsolicited messages."),
        }]
    elif ext in MODERATE_RISK_EXTENSIONS:
        score = MODERATE_RISK_EXTENSIONS[ext]
        indicators = [{
            "indicator": "moderate_risk_attachment",
            "severity": "medium",
            "score": score,
            "reason": (f"The file extension '{ext}' is an archive or "
                       "macro-enabled document. These are legitimate in "
                       "everyday use but are also a common malware/macro "
                       "delivery format in phishing."),
        }]
    else:
        score = 0.0
        indicators = []

    return {
        "filename": name,
        "attachment_present": True,
        "extension": ext,
        "risk_score": int(round(score)),
        "risk_level": _level(score),
        "is_suspicious": int(round(score)) >= 50,
        "indicators": indicators,
    }


__all__ = [
    "analyze_attachment_filename",
    "HIGH_RISK_EXTENSIONS",
    "MODERATE_RISK_EXTENSIONS",
]