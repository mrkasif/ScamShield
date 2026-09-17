"""ScamShield Safety-Zone and explainable risk-presentation helpers.

This module derives the unified GREEN / YELLOW / RED safety zone from the
EXISTING authoritative 0-100 risk score and builds two explainability blocks
from evidence the engines ALREADY produced:

* ``risk_assessment`` - score, zone, level, confidence, summary and a list of
  human-readable reasons, each backed by a real detected indicator.
* ``risk_breakdown`` - a truthful factor breakdown. Numeric contributions are
  ONLY included when the underlying engine exposes a per-detector score in its
  explanation output; otherwise the factors are explicitly labeled as detected
  indicators (no fabricated numbers). It NEVER changes the authoritative score.

Hard guarantees:

* No second scoring system. The zone is a pure function of ``risk_score``.
* Boundary behavior is deterministic: 0-24 GREEN, 25-59 YELLOW, 60-100 RED.
* Only evidence already present in the result is used - no fake reasons, no
  invented signals, no LLM, no network access anywhere.
"""

from __future__ import annotations

__all__ = [
    "GREEN", "YELLOW", "RED",
    "ZONES",
    "zone_for_score",
    "build_risk_assessment",
    "build_risk_breakdown",
    "attach_risk_presentation",
]

GREEN = "green"
YELLOW = "yellow"
RED = "red"

# Ordered ranking so zones can be compared/sorted deterministically.
ZONE_RANK = {GREEN: 0, YELLOW: 1, RED: 2}

# ---------------------------------------------------------------------------
# Zone definitions (single source of truth for the zone vocabulary)
# ---------------------------------------------------------------------------

ZONES = {
    GREEN: {
        "zone": GREEN,
        "label": "MINIMAL / NO THREAT",
        "description": "No significant malicious indicators detected.",
        "recommended_action": "Continue normally.",
        "range": "0-24",
    },
    YELLOW: {
        "zone": YELLOW,
        "label": "RISK / CAUTION",
        "description": "Risk indicators detected. The input may be unsafe.",
        "recommended_action": "Continue only after verifying the source.",
        "range": "25-59",
    },
    RED: {
        "zone": RED,
        "label": "DANGEROUS / HIGH RISK",
        "description": "Strong evidence of malicious or scam behavior.",
        "recommended_action": "STOP — Do not proceed.",
        "range": "60-100",
    },
}


def zone_for_score(score) -> dict:
    """Map the existing 0-100 risk score to a safety zone.

    Deterministic boundaries:
        0-24  -> GREEN  ("MINIMAL / NO THREAT")
        25-59 -> YELLOW ("RISK / CAUTION")
        60-100-> RED    ("DANGEROUS / HIGH RISK")

    Returns a dict with: zone, zone_label, zone_description,
    recommended_action, zone_range, score.
    """
    normalized = _clamp_score(score)
    if normalized >= 60:
        info = ZONES[RED]
    elif normalized >= 25:
        info = ZONES[YELLOW]
    else:
        info = ZONES[GREEN]
    return {
        "zone": info["zone"],
        "zone_label": info["label"],
        "zone_description": info["description"],
        "recommended_action": info["recommended_action"],
        "zone_range": info["range"],
        "score": normalized,
    }


def _clamp_score(value) -> int:
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        score = 0
    return max(0, min(100, score))


# ---------------------------------------------------------------------------
# Explainable "risk assessment" reasons  (one phrase per real indicator)
# ---------------------------------------------------------------------------

REASON_PHRASES = {
    # Domain intelligence
    "unusual_tld": "Suspicious top-level domain detected",
    "suspicious_tld_introduced": "Suspicious top-level domain detected",
    "punycode_domain": "Punycode-encoded domain detected",
    "internationalized_host": "Internationalized (IDN) host detected",
    "mixed_script_host": "Mixed-script (homoglyph-style) characters in host detected",
    "ip_address_host": "Raw IP address used instead of a real domain",
    "numeric_domain": "Numeric-looking domain detected",
    "host_became_ip": "Host changed to a raw IP address",
    "excessive_hyphens": "Obfuscated domain structure (excessive hyphens)",
    "excessive_subdomains": "Obfuscated domain structure (excessive subdomains)",
    "long_hostname": "Unusually long hostname detected",
    "domain_complexity_increased": "Domain complexity increased versus the baseline",
    # URL structure
    "http_scheme": "Plain, unencrypted HTTP scheme detected",
    "plain_http_introduced": "Plain HTTP scheme introduced",
    "unusual_scheme": "Unusual URL scheme detected",
    "unusual_port": "Unusual port detected",
    "port_changed": "Port changed versus the baseline",
    "long_url": "Unusually long URL detected",
    "excessive_separators": "Excessive separators used to obfuscate the URL",
    "link_changed_from_baseline": "Link changed from the previously observed baseline",
    # Phishing indicators
    "suspicious_keyword": "Credential-harvesting keyword indicators detected",
    "keyword_cluster": "Cluster of security-related words detected (typical of phishing pages)",
    "suspicious_link": "Suspicious link and click-pressure detected",
    # Brand impersonation
    "brand_impersonation": "Brand impersonation detected",
    "brand_in_subdomain": "Brand name placed in a sub-domain of an unrelated site",
    "brand_in_path": "Brand name placed in the path of an unrelated site",
    "possible_brand_typosquatting": "Possible brand typosquatting detected",
    "brand_similarity_introduced": "Brand similarity introduced versus the baseline",
    # Obfuscation
    "encoding_obfuscation": "Encoding obfuscation detected",
    "encoding_increased": "Percent-encoding obfuscation increased",
    "hex_encoded_host": "Hex-encoded host detected",
    "multiple_at": "Multiple '@' separators (obfuscation) detected",
    "confusing_userinfo": "Confusing userinfo segment detected",
    "embedded_credentials": "Embedded credentials in the URL detected",
    "obfuscation_present": "Obfuscation / hidden components detected",
    "unicode_or_homoglyph_introduced": "Unicode / homoglyph-style characters introduced",
    # Suspicious redirect
    "suspicious_redirect_parameter": "Suspicious redirect parameter detected",
    "redirect_parameter_present": "Redirect parameter detected",
    "redirect_parameter_added": "Redirect parameter added",
    "short_url_redirector": "Short-link redirector detected",
    # Nested / hidden destination
    "nested_url": "A complete address is nested inside the link",
    "encoded_nested_url": "An encoded destination is hidden inside the link",
    "nested_url_present": "Nested URL present in the link",
    "encoded_destination_present": "Encoded destination present in the link",
    "encoded_destination_appeared": "Encoded destination introduced",
    # Credential / OTP / KYC harvesting
    "otp_request": "OTP harvesting attempt detected",
    "credential_request": "Credential harvesting attempt detected",
    "credential_theft": "Credential-theft indicators detected",
    "kyc_request": "Fake KYC / identity-verification demand detected",
    "kyc_unblock_account_language": "Fake KYC / account-unblock language detected",
    # Payment indicators
    "upi_payment_uri": "UPI payment request embedded",
    "payment_destination_detected": "Unverified payment destination detected",
    "recipient_not_named": "Payment recipient is not named (cannot be verified)",
    "embedded_payment_amount": "Pre-filled payment amount flagged",
    "payment_amount_threshold_1": "Pre-filled amount over the warning threshold",
    "payment_amount_threshold_2": "Pre-filled amount over the high threshold",
    "urgent_payment_request": "Urgent payment-request language detected",
    "refund_reward_prize_language": "Advance-fraud reward / refund language detected",
    # Social engineering
    "urgency": "Urgency pressure detected",
}

# "(combination(...))" entries are real evidence from the URL engine.
_COMBINATION_PHRASE = "Combined evidence of multiple detected patterns"


def _reason_for(indicator: str) -> str:
    if indicator.startswith("combination("):
        return _COMBINATION_PHRASE
    phrase = REASON_PHRASES.get(indicator)
    if not phrase:
        human = str(indicator).replace("_", " ")
        phrase = f"Detected indicator: {human.strip().capitalize()}"
    return phrase


def _collect_indicators(result: dict) -> list[str]:
    """Ordered, deduplicated indicator list from indicators + explanation."""
    seen = []
    for indicator in list(result.get("indicators") or []):
        key = str(indicator).strip()
        if key and key not in seen:
            seen.append(key)
    for entry in result.get("explanation") or []:
        if isinstance(entry, dict):
            indicator = entry.get("indicator")
            if not indicator:
                continue
            key = str(indicator).strip()
            if key and key not in seen:
                seen.append(key)
    return seen


def _collect_reasons(result: dict, limit: int = 10) -> list[str]:
    """Human-readable reasons, each backed by a real detected signal."""
    phrases = []
    for indicator in _collect_indicators(result):
        phrase = _reason_for(indicator)
        if phrase not in phrases:
            phrases.append(phrase)
    return phrases[:limit]


# ---------------------------------------------------------------------------
# Truthful "risk factor breakdown" (no invented numbers)
# ---------------------------------------------------------------------------

_DOMAIN_FACTORS = frozenset({
    "unusual_tld", "suspicious_tld_introduced", "punycode_domain",
    "internationalized_host", "mixed_script_host", "ip_address_host",
    "numeric_domain", "host_became_ip", "excessive_hyphens",
    "excessive_subdomains", "long_hostname", "domain_complexity_increased",
    "hostname_changed", "root_domain_changed", "tld_changed",
    "subdomain_changed",
})

_URL_STRUCTURE_FACTORS = frozenset({
    "http_scheme", "plain_http_introduced", "unusual_scheme", "unusual_port",
    "port_changed", "path_changed", "fragment_changed", "scheme_changed",
    "long_url", "excessive_separators",
})

_PHISHING_FACTORS = frozenset({
    "suspicious_keyword", "keyword_cluster", "suspicious_link",
})

_BRAND_FACTORS = frozenset({
    "brand_impersonation", "brand_in_subdomain", "brand_in_path",
    "possible_brand_typosquatting", "brand_similarity_introduced",
})

_OBFUSCATION_FACTORS = frozenset({
    "encoding_obfuscation", "encoding_increased", "hex_encoded_host",
    "multiple_at", "confusing_userinfo", "embedded_credentials",
    "obfuscation_present", "unicode_or_homoglyph_introduced",
})

_REDIRECT_FACTORS = frozenset({
    "suspicious_redirect_parameter", "redirect_parameter_present",
    "redirect_parameter_added", "short_url_redirector",
})

_DESTINATION_FACTORS = frozenset({
    "nested_url", "encoded_nested_url", "nested_url_present",
    "encoded_destination_present", "encoded_destination_appeared",
})

_CREDENTIAL_FACTORS = frozenset({
    "otp_request", "credential_request", "credential_theft", "kyc_request",
    "kyc_unblock_account_language",
})

_PAYMENT_FACTORS = frozenset({
    "upi_payment_uri", "payment_destination_detected", "recipient_not_named",
    "embedded_payment_amount", "payment_amount_threshold_1",
    "payment_amount_threshold_2", "urgent_payment_request",
    "refund_reward_prize_language",
})

_SOCIAL_FACTORS = frozenset({"urgency"})

_FACTOR_ORDER = [
    ("Brand Impersonation", _BRAND_FACTORS),
    ("Phishing Indicators", _PHISHING_FACTORS),
    ("Suspicious Redirect", _REDIRECT_FACTORS),
    ("Embedded / Hidden Destination", _DESTINATION_FACTORS),
    ("Obfuscation", _OBFUSCATION_FACTORS),
    ("Domain Intelligence", _DOMAIN_FACTORS),
    ("URL Structure", _URL_STRUCTURE_FACTORS),
    ("Credential / OTP Harvesting", _CREDENTIAL_FACTORS),
    ("Payment Indicators", _PAYMENT_FACTORS),
    ("Urgency & Social Engineering", _SOCIAL_FACTORS),
]

_DEFAULT_FACTOR_CATEGORY = "Detection Signals"


def _factor_category(indicator: str) -> str:
    for name, members in _FACTOR_ORDER:
        if indicator in members:
            return name
    return _DEFAULT_FACTOR_CATEGORY


def _contribution(entry: dict) -> float:
    try:
        score = float(entry.get("score") or 0.0)
    except (TypeError, ValueError):
        score = 0.0
    return max(0.0, score)


def build_risk_breakdown(result: dict) -> dict:
    """Truthful factor breakdown built ONLY from existing detector evidence.

    An explanation entry that carries a per-detector ``score`` (as the URL and
    UPI engines emit) contributes a real number that feeds the engine's own
    scoring. When an engine does not expose per-detector contributions (e.g.
    the message engine), the factor is listed with its detected indicators and
    NO numeric contribution, and the block is labeled ``detected_factors``.
    The authoritative ``risk_score`` is never modified.
    """
    buckets = {}

    def _add(indicator: str, contribution: float):
        category = _factor_category(indicator)
        bucket = buckets.setdefault(category, {"indicators": set(), "contribution": 0.0})
        bucket["indicators"].add(indicator)
        bucket["contribution"] += contribution

    for entry in result.get("explanation") or []:
        if not isinstance(entry, dict):
            continue
        indicator = entry.get("indicator")
        if not indicator:
            indicator = "pattern"
        _add(str(indicator), _contribution(entry))

    # Make sure every reported indicator appears in the breakdown even if the
    # explanation omitted it (contribution stays 0 for those).
    for indicator in result.get("indicators") or []:
        _add(str(indicator), 0.0)

    total = round(sum(b["contribution"] for b in buckets.values()))
    has_contributions = any(b["contribution"] > 0 for b in buckets.values())

    factors = []
    for category in sorted(buckets, key=lambda k: (-buckets[k]["contribution"], k)):
        bucket = buckets[category]
        factor = {
            "category": category,
            "indicators": sorted(bucket["indicators"]),
        }
        if bucket["contribution"] > 0:
            factor["contribution"] = round(bucket["contribution"], 1)
        else:
            factor["contribution"] = None
        factors.append(factor)

    if has_contributions:
        block_type = "engine_score_contributions"
        note = (
            "Numeric contributions are the engine's own per-detector scores "
            "already present in its explanation output (the same entries that "
            "feed the existing scorer). They are grouped by factor for "
            "readability; the engine caps its final score, so the summed "
            "contributions may exceed the authoritative total."
        )
    else:
        block_type = "detected_factors"
        note = (
            "This engine does not expose granular per-detector score "
            "contributions, so no numeric values are shown. The factors are the "
            "actually detected indicators only. The authoritative existing "
            "risk score is unchanged."
        )

    return {
        "label": "Risk Factor Breakdown",
        "type": block_type,
        "note": note,
        "factors": factors,
        "total_contributions": total if has_contributions else None,
        "authoritative_score": _clamp_score(result.get("risk_score", 0)),
    }


# ---------------------------------------------------------------------------
# Structured risk assessment + top-level attachment
# ---------------------------------------------------------------------------

def build_risk_assessment(result: dict) -> dict:
    score = _clamp_score(result.get("risk_score", 0))
    zone = zone_for_score(score)
    return {
        "score": score,
        "zone": zone["zone"],
        "level": result.get("risk_level") or "LOW",
        "confidence": result.get("confidence", 0),
        "summary": result.get("summary")
        or (zone["zone_description"] if result.get("success") is False
            else zone["zone_description"]),
        "reasons": _collect_reasons(result),
    }


def attach_risk_presentation(result: dict) -> dict:
    """Add the safety zone + explainability keys to a unified result.

    Additive and backward-compatible: every existing key keeps its exact
    meaning; only new keys are introduced. Deterministic and offline.
    """
    if not isinstance(result, dict):
        return result
    out = dict(result)
    zone = zone_for_score(out.get("risk_score", 0))
    out["zone"] = zone["zone"]
    out["zone_label"] = zone["zone_label"]
    out["zone_description"] = zone["zone_description"]
    out["recommended_action"] = zone["recommended_action"]
    out["risk_assessment"] = build_risk_assessment(out)
    out["risk_breakdown"] = build_risk_breakdown(out)
    return out