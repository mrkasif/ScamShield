"""Transparent weighted risk scoring for the ScamShield URL engine.

Design
------
Each indicator contributes an explicit number of points (see indicators.py).
The total is:

    total = sum(indicator points)
            + combination bonuses       # strong pairs shown below
    total = clamp(total, 0, 100)

Points are explicit per-indicator values, not weight-multiplier products, so
every contribution can be explained exactly.

Guards
------
* Keywords alone are capped (KEYWORD_HIT_CAP * per-hit points) - a long list
  of security words without any structural evidence cannot reach HIGH by
  itself.
* Combination bonuses only apply between *related strong* indicators (e.g.
  IP-host + keyword, brand + keyword, credentials + keyword), so a single weak
  signal can never cascade to CRITICAL.

Risk levels (same bands as the message engine):
    0-24   LOW
    25-49  MEDIUM
    50-74  HIGH
    75-100 CRITICAL

A URL is "suspicious" when its score is 50 or higher.
"""

from __future__ import annotations

# Combination bonuses: when both indicators are present, these points are added.
# Names must exactly match the "indicator" values produced in indicators.py.
COMBINATIONS: tuple[tuple[str, str, float], ...] = (
    ("ip_address_host", "suspicious_keyword", 8.0),
    ("ip_address_host", "unusual_port", 6.0),
    ("embedded_credentials", "http_scheme", 8.0),
    ("embedded_credentials", "suspicious_keyword", 6.0),
    ("embedded_credentials", "unusual_scheme", 8.0),
    ("brand_impersonation", "suspicious_keyword", 8.0),
    ("brand_impersonation", "suspicious_redirect_parameter", 6.0),
    ("punycode_domain", "suspicious_keyword", 6.0),
    ("excessive_subdomains", "suspicious_keyword", 6.0),
    ("short_url_redirector", "suspicious_keyword", 8.0),
    ("unusual_port", "suspicious_keyword", 6.0),
    ("unusual_scheme", "suspicious_keyword", 8.0),
    ("encoding_obfuscation", "suspicious_keyword", 6.0),
    ("suspicious_redirect_parameter", "suspicious_keyword", 8.0),
    ("confusing_userinfo", "suspicious_keyword", 6.0),
    ("multiple_at", "suspicious_keyword", 6.0),
    # v2: brand-in-subdomain + typosquatting + unicode + query-param pairs
    ("brand_in_subdomain", "suspicious_keyword", 4.0),
    ("possible_brand_typosquatting", "suspicious_keyword", 6.0),
    ("possible_brand_typosquatting", "brand_impersonation", 6.0),
    ("mixed_script_host", "suspicious_keyword", 6.0),
    ("internationalized_host", "suspicious_keyword", 4.0),
    ("suspicious_query_param", "suspicious_keyword", 6.0),
    ("nested_url", "encoding_obfuscation", 8.0),
    ("excessive_hyphens", "suspicious_keyword", 4.0),
)

THRESHOLD_SUSPICIOUS: float = 50.0

# Cross-detector point caps. The family names must match indicator names.
#   - the "long URL" complexity family is capped together so stacking
#     long_url + long_hostname + long_path + many_query_parameters cannot
#     blow up the score on size alone;
#   - suspicious query-param points are capped at two params.
COMPLEXITY_FAMILY: frozenset[str] = frozenset({
    "long_url", "long_hostname", "long_path", "many_query_parameters",
})
COMPLEXITY_CAP: float = 20.0
QUERY_PARAM_FAMILY: frozenset[str] = frozenset({"suspicious_query_param"})
QUERY_PARAM_CAP: float = 10.0

_CAPS: tuple[tuple[frozenset[str], float], ...] = (
    (COMPLEXITY_FAMILY, COMPLEXITY_CAP),
    (QUERY_PARAM_FAMILY, QUERY_PARAM_CAP),
)


def _risk_level(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def score_url(findings: list[dict]) -> dict:
    """Collapse detector findings into a scored result.

    Returns:
        total           float 0-100 (before rounding)
        risk_score      int 0-100
        risk_level      LOW/MEDIUM/HIGH/CRITICAL
        is_suspicious   bool
        confidence      int 0-100 (deterministic heuristic)
        indicator_names list[str]
        bonuses         list[dict]  {indicator, severity, score, reason}
        contributions   list[dict]  indicator entries with their points
    """
    total = 0.0
    present: set[str] = set()
    contributions: list[dict] = []
    for f in findings:
        total += float(f["score"])
        present.add(f["indicator"])
        contributions.append({
            "indicator": f["indicator"],
            "severity": f["severity"],
            "score": float(f["score"]),
            "reason": f["reason"],
            "evidence": f.get("evidence"),
        })

    _apply_group_caps(contributions)
    total = sum(float(c["score"]) for c in contributions)

    bonuses: list[dict] = []
    for a, b, bonus in COMBINATIONS:
        if a in present and b in present:
            total += bonus
            bonuses.append({
                "indicator": f"combination({a}+{b})",
                "severity": "low",
                "score": bonus,
                "reason": ("Combination rule: " + a.replace("_", " ") +
                           " together with " + b.replace("_", " ") +
                           " is much stronger evidence than either alone."),
            })

    total = max(0.0, min(100.0, total))
    risk_score = int(round(total))
    risk_score = max(0, min(100, risk_score))
    level = _risk_level(risk_score)
    is_suspicious = risk_score >= THRESHOLD_SUSPICIOUS

    confidence = _confidence(total, len(contributions))

    return {
        "total": round(total, 2),
        "risk_score": risk_score,
        "risk_level": level,
        "is_suspicious": is_suspicious,
        "confidence": confidence,
        "indicator_names": sorted(present),
        "bonuses": bonuses,
        "contributions": contributions,
    }


def _confidence(total: float, count: int) -> int:
    """Deterministic confidence heuristic based on score + evidence count."""
    if count == 0:
        return 0
    c = 40.0 + total * 0.6 + min(count, 8) * 2.5
    return int(max(0, min(100, round(c))))


def _apply_group_caps(contributions: list[dict]) -> None:
    """Scale down indicator families that exceed their cross-detector cap.

    Contributions are mutated in place so the totals always match the
    explanation list exactly (fully transparent scoring).
    """
    for family, cap in _CAPS:
        idx = [i for i, c in enumerate(contributions) if c["indicator"] in family]
        if not idx:
            continue
        subtotal = sum(float(contributions[i]["score"]) for i in idx)
        if subtotal <= cap:
            continue
        factor = cap / subtotal
        for i in idx:
            contributions[i]["score"] = round(
                float(contributions[i]["score"]) * factor, 2)


# ---------------------------------------------------------------------------
# Combined message + URL risk
# ---------------------------------------------------------------------------

def combine_message_and_urls(message_score: int, url_scores: list[int]) -> dict:
    """Combine a message risk score with its extracted URL risk scores.

    Rule (documented, deterministic, capped at 100):

        strongest = max(message_score, strongest_url_score)
        weakest   = min(message_score, strongest_url_score)
        C = strongest + (100 - strongest) * (weakest / 100) * 0.7

    * When there is no URL, C == message_score.
    * C is always >= every component signal (the overall verdict can never
      drop below the strongest piece of evidence the engine found).
    * Roughly 70% of the remaining headroom of the strongest signal is
      consumed by the second, weaker signal, so two strong signals combine
      into a higher capped score than either alone.
    * C is always in 0-100.

    Returns {score, level, message_score, url_scores}.
    """
    m = int(max(0, min(100, message_score)))
    u = [int(max(0, min(100, s))) for s in url_scores]
    if not u:
        score = m
    else:
        strongest = max(m, max(u))
        weakest = min(m, max(u))
        score = int(round(strongest + (100 - strongest) * (weakest / 100.0) * 0.7))
        score = int(max(0, min(100, score)))
    return {
        "score": score,
        "level": _risk_level(score),
        "message_score": m,
        "url_scores": u,
    }