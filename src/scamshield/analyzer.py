"""ScamShield Unified Analyzer - orchestration layer.

Public API (framework-independent - a future HTTP API / UI calls these directly):

    analyze(input_type, content, **metadata) -> dict
    detect_input_type(content) -> str
    analyze_batch(items) -> list[dict]

This module is an ORCHESTRATOR, not another detection engine. It never
re-implements message rules, URL rules, QR rules, UPI rules or scoring. It
calls the existing engines and normalizes their outputs into one consistent
result schema:

    scamshield.nlp.analyze_message()   ("message")
    scamshield.url.analyze_url()       ("url")
    scamshield.qr.analyze_qr()         ("qr" - image path)
    scamshield.qr.analyze_qr_content() ("upi" - a decoded UPI URI string)

Security: inherits the restrictions of the underlying engines - fully local,
deterministic, no network requests, no URL opening, no payment execution, no
external APIs, no API keys.
"""

from __future__ import annotations

import re
from pathlib import Path

from .nlp import analyze_message
from .qr import analyze_qr as _analyze_qr
from .qr import analyze_qr_content as _analyze_qr_content
from .url import analyze_url as _analyze_url

__all__ = ["analyze", "analyze_batch", "detect_input_type", "analyze_chain"]

# ---------------------------------------------------------------------------
# Input type handling
# ---------------------------------------------------------------------------

CANONICAL_TYPES = ("message", "url", "qr", "upi", "chain")

TYPE_ALIASES = {
    "message": "message", "msg": "message", "text": "message",
    "url": "url", "link": "url",
    "qr": "qr", "qrcode": "qr", "qr_image": "qr", "image": "qr",
    "upi": "upi", "upi_uri": "upi",
    "chain": "chain", "chain_analysis": "chain", "multistage": "chain",
}

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# Normalized scam-type vocabulary (same families the message engine produces).
SCAM_TYPE_VOCABULARY = frozenset({
    "phishing", "fake_kyc", "upi_payment", "bank_impersonation",
    "fake_customer_care", "job_scam", "investment_scam", "loan_scam",
    "delivery_scam", "lottery_prize", "social_media_impersonation",
    "government_impersonation", "credential_theft", "other", "safe",
})

CONFIDENCE_NOTE = (
    "Heuristic confidence estimate, not a calibrated statistical probability."
)

# Short human labels for URL indicators used in summaries/evidence.
URL_FEATURE_LABELS = {
    "http_scheme": "plain HTTP",
    "unusual_scheme": "an unusual scheme",
    "ip_address_host": "a raw IP address host",
    "punycode_domain": "a punycode-encoded domain",
    "internationalized_host": "an internationalized (IDN) host",
    "mixed_script_host": "mixed-script characters",
    "embedded_credentials": "embedded credentials",
    "long_url": "an unusually long URL",
    "unusual_port": "an unusual port",
    "encoding_obfuscation": "encoding obfuscation",
    "nested_url": "a nested URL",
    "encoded_nested_url": "an encoded nested URL",
    "hex_encoded_host": "a hex-encoded host",
    "confusing_userinfo": "a confusing userinfo segment",
    "multiple_at": "multiple '@' characters",
    "excessive_separators": "excessive separators",
    "excessive_hyphens": "excessive hyphens",
    "numeric_domain": "a numeric-looking domain",
    "short_url_redirector": "a short-link redirector",
    "suspicious_keyword": "suspicious keywords",
    "keyword_cluster": "a cluster of security words",
    "suspicious_redirect_parameter": "a suspicious redirect parameter",
    "suspicious_query_param": "suspicious query parameters",
    "brand_impersonation": "possible brand impersonation",
    "brand_in_subdomain": "a brand word in a sub-domain",
    "brand_in_path": "a brand word in the path",
    "possible_brand_typosquatting": "possible typosquatting",
    "unusual_tld": "an unusual TLD",
}


def _normalize_input_type(input_type) -> str | None:
    if not isinstance(input_type, str):
        return None
    key = input_type.strip().lower()
    return TYPE_ALIASES.get(key)


def detect_input_type(content) -> str:
    """Conservatively guess whether text looks like a URL, UPI URI or message.

    Returns one of: "url", "upi", "message". Only exact scheme prefixes
    (http://, https://, upi:) are recognized - a bare "example.com" or an image
    path is never auto-guessed, so uncertain inputs fall back to "message"
    instead of a dangerous guess.
    """
    if not isinstance(content, str):
        return "message"
    text = content.strip()
    if re.match(r"^https?://", text, re.IGNORECASE):
        return "url"
    if re.match(r"^upi:(//)?", text, re.IGNORECASE):
        return "upi"
    return "message"


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def _risk_level(score: float) -> str:
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def _normalize_score(value) -> int:
    try:
        return max(0, min(100, int(round(float(value)))))
    except (TypeError, ValueError):
        return 0


def _normalize_level(score: int, engine_level) -> str:
    if isinstance(engine_level, str):
        level = engine_level.strip().upper()
        if level in RISK_LEVELS:
            return level
    return _risk_level(score)


def _normalize_scam_type(value, suspicious: bool) -> str | None:
    if not value:
        return "phishing" if suspicious else "safe"
    key = str(value).strip().lower()
    if key in SCAM_TYPE_VOCABULARY:
        return key
    return "other" if suspicious else "safe"


def _normalize_explanation_entry(entry: dict) -> dict:
    """Give every explanation entry the common {indicator, severity, score,
    reason, evidence} shape regardless of the source engine."""
    score = entry.get("score")
    if score is None:
        score = 0.0
    else:
        try:
            score = round(float(score), 2)
        except (TypeError, ValueError):
            score = 0.0
    return {
        "indicator": entry.get("indicator", "pattern") or "pattern",
        "severity": (entry.get("severity") or "low").lower(),
        "score": score,
        "reason": entry.get("reason") or "A risk pattern was detected.",
        "evidence": entry.get("evidence") or "",
    }


def _collect_explanations(engine_result: dict) -> list[dict]:
    raw = engine_result.get("explanation")
    if raw is None:
        raw = engine_result.get("explanations") or []
    return [_normalize_explanation_entry(e) for e in raw]


def _collect_indicators(engine_result: dict) -> list[str]:
    indicators = engine_result.get("indicators")
    if indicators is None:
        indicators = engine_result.get("detected_indicators")
    return [str(i) for i in (indicators or [])]


def _collect_recommendations(engine_result: dict) -> list[str]:
    return [str(r) for r in (engine_result.get("recommendations") or [])]


def _unique_preserve_order(values) -> list:
    seen = set()
    out = []
    for value in values:
        if isinstance(value, str):
            key = value.strip().lower()
        else:
            key = repr(value)
        if key and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def _error_result(
    input_type: str,
    error: str,
    error_type: str = "validation",
) -> dict:
    return {
        "success": False,
        "input_type": input_type,
        "status": "ERROR",
        "error": error,
        "error_type": error_type,
        "risk_score": 0,
        "risk_level": "LOW",
        "is_suspicious": False,
        "scam_type": None,
        "confidence": 0,
        "confidence_type": "heuristic",
        "confidence_note": CONFIDENCE_NOTE,
        "summary": "The input could not be analysed.",
        "indicators": [],
        "explanation": [],
        "recommendations": ["Correct the input and retry the analysis."],
        "evidence": {"source": input_type},
        "engine_results": {},
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# Summary generation (deterministic, evidence-based, no LLM)
# ---------------------------------------------------------------------------

def _summarize_message(engine_result: dict, suspicious: bool,
                       scam_type: str) -> str:
    level = engine_result.get("risk_level") or "LOW"
    indicators = engine_result.get("detected_indicators") or []
    if not suspicious:
        return f"No scam patterns were detected in this message ({level} risk)."

    label = scam_type.replace("_", " ")
    sentence = f"{level.capitalize()}-risk message classified as a {label} scam."
    evidence_bits = []
    if "urgency" in indicators:
        evidence_bits.append("urgency pressure")
    if "otp_request" in indicators:
        evidence_bits.append("an OTP request")
    if "credential_request" in indicators:
        evidence_bits.append("a credential request")
    url_analyses = engine_result.get("url_analysis") or []
    if url_analyses:
        if any(u.get("is_suspicious") for u in url_analyses):
            evidence_bits.append("a suspicious URL")
        else:
            evidence_bits.append("an embedded URL")
    if evidence_bits:
        sentence += f" Evidence: {', '.join(evidence_bits)}."
    return sentence


def _summarize_url(engine_result: dict, suspicious: bool) -> str:
    parse = engine_result.get("parse") or {}
    domain = parse.get("root_domain") or parse.get("hostname")
    url = engine_result.get("url") or ""
    label = domain or url or "the URL"
    if not suspicious:
        return f"The URL ({label}) shows no significant risk indicators."
    indicators = _collect_indicators(engine_result)
    features = [
        URL_FEATURE_LABELS[name] for name in indicators
        if name in URL_FEATURE_LABELS
    ]
    if not features:
        features = [f"{len(indicators)} structural risk indicator(s)"]
    joined = _join_features(features)
    return f"Suspicious URL ({label}) with {joined}."


def _summarize_upi(engine_result: dict, suspicious: bool) -> str:
    upi = (engine_result.get("upi_analysis") or {}).get("parse") or {}
    payee = upi.get("payee_name") or upi.get("payee_address")
    amount = upi.get("amount")
    note_indicators = {
        "urgent_payment_request", "refund_reward_prize_language",
        "kyc_unblock_account_language", "otp_credential_request",
    }
    has_note = bool(
        note_indicators.intersection(_collect_indicators(engine_result))
    )

    details = []
    if payee:
        details.append(f"for {payee}")
    if amount is not None:
        details.append(f"with a pre-filled amount of {amount}")
    if has_note:
        details.append("with suspicious transaction-note language")
    tail = " " + " ".join(details) if details else ""

    if suspicious:
        payee_part = f" to {payee}" if payee else ""
        amount_part = f" (amount {amount})" if amount is not None else ""
        note_part = " with suspicious transaction-note language" if has_note else ""
        return (
            f"A suspicious UPI payment request{payee_part}{amount_part}"
            f"{note_part} was flagged."
        )
    return f"A UPI payment request{tail} was analysed - no strong risk indicators were detected."


def _summarize_qr(engine_result: dict, suspicious: bool) -> str:
    status = engine_result.get("status") or "DECODED"
    if status == "ERROR":
        return "The QR image could not be decoded."
    if status == "NOT DECODED":
        return "No QR code was detected in the image."

    prefix = ""
    if engine_result.get("multiple_codes"):
        prefix = (
            f"This image contains {engine_result.get('decoded_count', 2)} QR "
            "codes; "
        )
    content_type = engine_result.get("content_type")

    if content_type == "url":
        url_analysis = engine_result.get("url_analysis") or {}
        inner = _summarize_url(url_analysis, suspicious)
        return f"{prefix}QR code decodes to a URL. {inner}"
    if content_type == "upi":
        upi_analysis = engine_result.get("upi_analysis") or {}
        parse = upi_analysis.get("parse") or {}
        bits = []
        if parse.get("payee_address") or parse.get("payee_name"):
            bits.append("a payment destination")
        if parse.get("amount") is not None:
            bits.append(f"a pre-filled amount of {parse['amount']}")
        bits_str = " with " + " and ".join(bits) if bits else ""
        if suspicious:
            return f"{prefix}QR code contains a suspicious UPI payment URI{bits_str}."
        return f"{prefix}QR code contains a UPI payment request{bits_str}."
    if content_type == "text":
        message_analysis = engine_result.get("message_analysis") or {}
        scam_type = _normalize_scam_type(
            message_analysis.get("scam_type"), suspicious
        )
        inner = f"decodes to a {scam_type.replace('_', ' ')} text payload"
        return f"{prefix}QR code {inner} with {message_analysis.get('risk_level', 'LOW')} risk."
    if content_type == "unknown":
        return (
            f"{prefix}QR code content is not a recognizable URL, UPI URI or "
            "message. No malicious classification was made."
        )
    return f"{prefix}QR code was analysed with {content_type or 'unknown'} content."


def _join_features(features: list[str]) -> str:
    if len(features) == 1:
        return features[0]
    if len(features) == 2:
        return f"{features[0]} and {features[1]}"
    return f"{', '.join(features[:-1])} and {features[-1]}"


def _summarize(input_type: str, engine_result: dict, suspicious: bool,
               scam_type: str) -> str:
    if input_type == "message":
        return _summarize_message(engine_result, suspicious, scam_type)
    if input_type == "url":
        return _summarize_url(engine_result, suspicious)
    if input_type == "upi":
        return _summarize_upi(engine_result, suspicious)
    return _summarize_qr(engine_result, suspicious)


# ---------------------------------------------------------------------------
# Evidence generation (only includes information actually available)
# ---------------------------------------------------------------------------

def _domains_from_url_analyses(url_analyses) -> list[str]:
    domains = []
    for analysis in url_analyses or []:
        parse = (analysis or {}).get("parse") or {}
        for key in ("root_domain", "hostname"):
            value = parse.get(key)
            if value and value not in domains:
                domains.append(value)
    return domains


def _evidence_message(engine_result: dict) -> dict:
    evidence = {"source": "message"}
    urls = list(engine_result.get("detected_urls") or [])
    if urls:
        evidence["urls"] = urls
    domains = _domains_from_url_analyses(engine_result.get("url_analysis"))
    if domains:
        evidence["domains"] = domains
    return evidence


def _evidence_url(engine_result: dict) -> dict:
    parse = engine_result.get("parse") or {}
    evidence = {"source": "url"}
    url = engine_result.get("url")
    if url:
        evidence["urls"] = [url]
    domains = []
    for key in ("root_domain", "hostname"):
        value = parse.get(key)
        if value and value not in domains:
            domains.append(value)
    if domains:
        evidence["domains"] = domains
    # Never surface credentials stored in a URL (parse keeps username/password).
    for key in ("scheme", "hostname", "root_domain", "subdomains", "tld",
                "port", "path", "query", "fragment"):
        value = parse.get(key)
        if value not in (None, ""):
            evidence[f"url_{key}"] = value
    return evidence


def _evidence_upi(engine_result: dict) -> dict:
    upi = (engine_result.get("upi_analysis") or {}).get("parse") or {}
    fields = {}
    for key in ("payee_address", "payee_name", "amount", "currency",
                "transaction_note", "merchant_code", "transaction_ref",
                "action", "is_pay", "valid_upi", "malformed"):
        value = upi.get(key)
        if value not in (None, ""):
            fields[key] = value
    evidence = {"source": "upi"}
    if fields:
        evidence["upi"] = fields
    return evidence


def _evidence_qr(engine_result: dict) -> dict:
    evidence = {"source": "qr"}
    for key in ("file", "status", "content_type", "decoded", "decoded_count",
                "multiple_codes"):
        if engine_result.get(key) not in (None, ""):
            evidence[key] = engine_result[key]
    codes = engine_result.get("codes")
    if codes:
        evidence["codes"] = list(codes)
    if engine_result.get("decoded_content") is not None:
        evidence["decoded_content"] = engine_result["decoded_content"]

    upi = (engine_result.get("upi_analysis") or {}).get("parse") or {}
    upi_fields = {}
    for key in ("payee_address", "payee_name", "amount", "currency",
                "transaction_note", "merchant_code", "transaction_ref"):
        value = upi.get(key)
        if value not in (None, ""):
            upi_fields[key] = value
    if upi_fields:
        evidence["upi"] = upi_fields

    url_analysis = engine_result.get("url_analysis")
    if url_analysis:
        urls = [url_analysis.get("url")] if url_analysis.get("url") else []
        if urls:
            evidence["urls"] = urls
        domains = _domains_from_url_analyses([url_analysis])
        if domains:
            evidence["domains"] = domains
    return evidence


def _evidence(input_type: str, engine_result: dict) -> dict:
    if input_type == "message":
        return _evidence_message(engine_result)
    if input_type == "url":
        return _evidence_url(engine_result)
    if input_type == "upi":
        return _evidence_upi(engine_result)
    return _evidence_qr(engine_result)


# ---------------------------------------------------------------------------
# Scam-type normalization per input type
# ---------------------------------------------------------------------------

def _scam_type(input_type: str, engine_result: dict, suspicious: bool) -> str | None:
    if input_type == "message":
        return _normalize_scam_type(engine_result.get("scam_type"), suspicious)
    if input_type == "url":
        return "phishing" if suspicious else "safe"
    if input_type == "upi":
        return "upi_payment" if suspicious else "safe"
    # QR
    status = engine_result.get("status")
    if status == "ERROR":
        return None
    if status == "NOT DECODED":
        return "safe"
    content_type = engine_result.get("content_type")
    if content_type == "url":
        return "phishing" if suspicious else "safe"
    if content_type == "upi":
        return "upi_payment" if suspicious else "safe"
    if content_type == "text":
        message_analysis = engine_result.get("message_analysis") or {}
        return _normalize_scam_type(message_analysis.get("scam_type"), suspicious)
    if content_type == "unknown":
        return "other" if suspicious else "safe"
    return "other" if suspicious else "safe"


def _warnings(input_type: str, engine_result: dict, suspicious: bool) -> list[str]:
    warnings = [CONFIDENCE_NOTE]
    engine_warning = engine_result.get("warning")
    if isinstance(engine_warning, str):
        warnings.append(engine_warning)
    if input_type == "url":
        parse = engine_result.get("parse") or {}
        if not parse.get("hostname") and engine_result.get("url"):
            warnings.append(
                "The input did not parse as a complete URL (no host detected); "
                "it was analysed as-is."
            )
    if input_type == "qr" and engine_result.get("success") is False:
        warnings.append("The QR image could not be decoded.")
    return warnings


# ---------------------------------------------------------------------------
# Core result assembly (single source of truth for the unified schema)
# ---------------------------------------------------------------------------

def _build_unified(input_type: str, engine_result: dict, metadata: dict,
                   extra_engine_results: dict | None = None) -> dict:
    score = _normalize_score(engine_result.get("risk_score", 0))
    level = _normalize_level(score, engine_result.get("risk_level"))

    suspicious = engine_result.get("is_suspicious")
    if suspicious is None:
        suspicious = engine_result.get("is_scam", False)
    suspicious = bool(suspicious)

    scam_type = _scam_type(input_type, engine_result, suspicious)
    confidence = engine_result.get("confidence", 0)
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        confidence = 0.0

    engine_results = {input_type: engine_result}
    if extra_engine_results:
        for key, value in extra_engine_results.items():
            if key not in engine_results:
                engine_results[key] = value

    return {
        "success": True,
        "input_type": input_type,
        "status": engine_result.get("status", "ANALYSED"),
        "risk_score": score,
        "risk_level": level,
        "is_suspicious": suspicious,
        "scam_type": scam_type,
        "confidence": confidence,
        "confidence_type": "heuristic",
        "confidence_note": CONFIDENCE_NOTE,
        "summary": _summarize(input_type, engine_result, suspicious, scam_type),
        "indicators": _collect_indicators(engine_result),
        "explanation": _collect_explanations(engine_result),
        "recommendations": _collect_recommendations(engine_result),
        "evidence": _evidence(input_type, engine_result),
        "engine_results": engine_results,
        "warnings": _warnings(input_type, engine_result, suspicious),
    }


# ---------------------------------------------------------------------------
# Per-input-type wrappers
# ---------------------------------------------------------------------------

def _run_ml(text: str) -> dict:
    """Run the local ML classifier on a message and return a structured result.

    The ML layer is an ADDITIONAL intelligence source that is kept strictly
    separate from the deterministic rule engine: we NEVER average or blend the
    two scores. The deterministic `risk_score` (from the rule engine) is the
    authoritative verdict; the ML result is exposed alongside it under
    `engine_results["ml_analysis"]`.

    If the trained model is unavailable (or an error occurs) this returns a
    graceful dict with `model_available=False` and never raises, so a missing
    model can never break the unified analyzer. Fully local - no network, no
    URL resolution, no payment, no external API, user text goes nowhere.
    """
    try:
        from .ml.predict import predict_message
    except Exception:  # ML package import must never break the analyzer
        return {
            "model_available": False,
            "prediction": None,
            "score": None,
            "confidence": None,
            "confidence_type": "unavailable",
            "warning": "ML model unavailable - the ML layer could not be loaded. "
                       "The deterministic message engine is used instead.",
        }
    try:
        return predict_message(text, model_path=_default_ml_model_path())
    except Exception as exc:
        return {
            "model_available": False,
            "prediction": None,
            "score": None,
            "confidence": None,
            "confidence_type": "unavailable",
            "warning": f"ML prediction failed ({type(exc).__name__}). "
                       "The deterministic message engine is used instead.",
            "error": str(exc),
        }


def _default_ml_model_path() -> str:
    """Resolve the ML model path robustly (repo-relative, not CWD-relative).

    Falls back to the CWD-relative default when the package cannot locate a
    repo root, so tests and other layouts still work.
    """
    try:
        from pathlib import Path as _Path

        pkg_dir = _Path(__file__).resolve().parent  # .../src/scamshield
        root = pkg_dir.parent.parent  # .../src/scamshield -> repo root
        candidate = root / "models" / "scamshield_tfidf.joblib"
        return str(candidate)
    except Exception:
        return "models/scamshield_tfidf.joblib"


def _analyze_message_input(content, metadata: dict) -> dict:
    if not isinstance(content, str):
        return _error_result(
            "message", "message content must be a string.", "validation"
        )
    engine_result = analyze_message(content)
    ml = _run_ml(content)
    return _build_unified("message", engine_result, metadata,
                          extra_engine_results={"ml_analysis": ml})


def _analyze_url_input(content, metadata: dict) -> dict:
    if not isinstance(content, str):
        return _error_result(
            "url", "url content must be a string.", "validation"
        )
    engine_result = _analyze_url(content)
    return _build_unified("url", engine_result, metadata)


def _analyze_upi_input(content, metadata: dict) -> dict:
    if not isinstance(content, str):
        return _error_result(
            "upi", "upi content must be a string.", "validation"
        )
    engine_result = _analyze_qr_content(content)
    return _build_unified("upi", engine_result, metadata)


def _analyze_qr_input(content, metadata: dict) -> dict:
    if isinstance(content, Path):
        content = str(content)
    if not isinstance(content, str):
        return _error_result(
            "qr", "qr content must be an image path (str or Path).", "validation"
        )
    engine_result = _analyze_qr(content)
    if engine_result.get("success") is False:
        error = engine_result.get("error") or "The QR image could not be decoded."
        built = _error_result("qr", error, "engine_error")
        built["engine_results"] = {"qr": engine_result}
        built["evidence"] = {"source": "qr", "file": str(content)}
        built["warnings"] = _warnings("qr", engine_result, False)
        return built
    return _build_unified("qr", engine_result, metadata)


def _analyze_chain_input(content, metadata: dict) -> dict:
    """Analyze an ordered collection of already-analyzed artifacts as a possible
    multi-stage scam chain.

    ``content`` is a list where each element is either a unified analyzer result
    (output of ``analyze(...)`` / ``analyze_batch(...)``), a raw engine result, or
    a structured stage dict. The chain layer is an ADDITIONAL correlation layer:
    it never re-runs message/URL/QR/UPI detection, never opens URLs or resolves
    DNS, and the individual engine results are preserved under
    ``engine_results["chain_per_stage"]``.

    The chain verdict is exposed in the SAME unified schema: ``risk_score``,
    ``risk_level``, ``is_suspicious``, ``classification``, ``chain_pattern``,
    ``relationships``, ``stages``, etc. Full per-stage engine results are retained
    in ``engine_results``.
    """
    from .chain import analyze_chain as _run_chain

    if isinstance(content, (str, bytes)):
        return _error_result(
            "chain",
            "chain content must be a list of already-analyzed artifacts.",
            "validation",
        )
    if not isinstance(content, (list, tuple)):
        return _error_result(
            "chain",
            "chain content must be a list of already-analyzed artifacts.",
            "validation",
        )

    items = list(content)
    chain_result = _run_chain(items)

    # Preserve the FULL original engine results of each supplied unified artifact.
    per_stage = []
    for item in items:
        if isinstance(item, dict):
            er = item.get("engine_results")
            per_stage.append(er if isinstance(er, dict) else {})
        else:
            per_stage.append({"stage": item})

    engine_results = {
        "chain": chain_result,
        "chain_per_stage": per_stage,
    }

    # Promote the chain verdict into the unified schema (only when chain mode).
    return {
        "success": True,
        "input_type": "chain",
        "status": "ANALYSED",
        "risk_score": chain_result["risk_score"],
        "risk_level": chain_result["risk_level"],
        "is_suspicious": chain_result["is_suspicious"],
        "scam_type": chain_result.get("chain_pattern") or (
            "multi_stage_scam" if chain_result["is_suspicious"] else "safe"
        ),
        "confidence": chain_result["confidence"],
        "confidence_type": "heuristic",
        "confidence_note": CONFIDENCE_NOTE,
        "summary": chain_result["summary"],
        "indicators": chain_result["indicators"],
        "explanation": chain_result["explanation"],
        "recommendations": chain_result["recommendations"],
        "evidence": chain_result["evidence"],
        "engine_results": engine_results,
        "warnings": list(chain_result["warnings"]),
        "classification": chain_result["classification"],
        "chain_pattern": chain_result["chain_pattern"],
        "stages": chain_result["stages"],
        "relationships": chain_result["relationships"],
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(input_type, content, **metadata) -> dict:
    """Analyze one input of the given type and return the unified result.

    Supported input types: "message", "url", "qr" (image path), "upi" (a
    decoded UPI URI string, routed through the QR content analyzer).

    Examples:
        analyze("message", "Your KYC has expired...")
        analyze("url", "https://example.com/login")
        analyze("qr", "tests/fixtures/qr/url_suspicious.png")
        analyze("upi", "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")

    Deterministic and fully local. Extra keyword metadata is accepted for
    forward compatibility with a future HTTP API and currently unused.

    The unified result always contains: success, input_type, risk_score,
    risk_level, is_suspicious, scam_type, confidence, confidence_type,
    confidence_note, summary, indicators, explanation, recommendations,
    evidence, engine_results (the full original engine result), warnings.
    """
    itype = _normalize_input_type(input_type)
    if itype is None:
        return _error_result(
            _normalize_raw_type(input_type),
            f"Unsupported input type {input_type!r}. Expected one of: "
            "message, url, qr, upi, chain.",
            "unsupported_type",
        )
    metadata = dict(metadata)
    if itype == "message":
        return _analyze_message_input(content, metadata)
    if itype == "url":
        return _analyze_url_input(content, metadata)
    if itype == "upi":
        return _analyze_upi_input(content, metadata)
    if itype == "chain":
        return _analyze_chain_input(content, metadata)
    return _analyze_qr_input(content, metadata)


def analyze_chain(stages_material) -> dict:
    """Analyze an ordered collection of already-analyzed artifacts as a possible
    multi-stage scam chain.

    This is the framework-independent chain entrypoint (the same one used by
    ``analyze("chain", [...])``). It accepts a list of unified analyzer results,
    raw engine results, or structured stage dicts and returns the chain result
    dict (classification, chain_pattern, risk_score, relationships, stages,
    explanation, recommendations, warnings).

    Fully offline: the chain layer never re-runs message/URL/QR/UPI detection and
    never opens URLs, resolves DNS, or contacts any external service.
    """
    from .chain import analyze_chain as _run_chain

    return _run_chain(stages_material)


def _normalize_raw_type(input_type) -> str:
    if isinstance(input_type, str) and input_type.strip():
        return input_type.strip()
    return "unknown"


def analyze_batch(items) -> list[dict]:
    """Analyze several independent inputs sequentially (no concurrency yet).

    Each item maps to one unified result:
        {"type": "url", "content": "https://example.com"}
        {"type": "message", "content": "..."}
        {"content": "upi://pay?..."}                     # type auto-detected
        ("qr", "tests/fixtures/qr/x.png")                # tuple form accepted

    Deterministic: results are returned in input order.
    """
    results = []
    for item in items:
        if isinstance(item, dict):
            itype = item.get("type")
            content = item.get("content")
            extra = {k: v for k, v in item.items() if k not in ("type", "content")}
        elif isinstance(item, (tuple, list)) and len(item) >= 2:
            itype, content = item[0], item[1]
            extra = {}
        else:
            results.append(_error_result(
                "unknown",
                "Each batch item must be a dict with 'type' and 'content', "
                "or a (type, content) tuple.",
                "validation",
            ))
            continue
        if not itype:
            itype = detect_input_type(content)
        results.append(analyze(itype, content, **extra))
    return results


__all__ = ["analyze", "analyze_batch", "detect_input_type", "analyze_chain"]