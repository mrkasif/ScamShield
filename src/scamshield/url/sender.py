"""Sender metadata heuristics for the ScamShield engine.

STATIC / INTERFACE ONLY - this module never sends mail, never resolves
anything and never fabricates data. It checks a purely textual property:
does the *display name* claim to be a known brand while the *sender address*
(or declared sender domain) is not something that brand owns?

    display "SBI Customer Care"   +   support@example.com   -> mismatch
    display "SBI Customer Care"   +   no-reply@sbi.co.in    -> consistent

This is the natural companion to the URL brand-impersonation logic and the
attachment heuristics; all three are pure static metadata checks.
"""

from __future__ import annotations

import re

from . import patterns as _p


def _brand_token_in(display: str) -> str | None:
    for token, profile in _p.BRAND_PROFILES.items():
        if profile.get("need_keyword"):
            continue  # generic tokens (upi/post) are too ambiguous for senders
        if re.search(r"(?<!\w)" + re.escape(token) + r"(?!\w)", display):
            return token
    return None


def assess_sender(display_name: str,
                  sender_email: str | None = None,
                  sender_domain: str | None = None) -> dict:
    """Check a sender's display name against its declared domain.

    Returns {sender_brand_mismatch: bool, matched_brand, indicators,
             risk_score, risk_level}.
    """
    display = (display_name or "").lower()
    domain = (sender_domain or "").lower().strip("[]")

    email = (sender_email or "").strip()
    if email and "@" in email:
        domain = email.rsplit("@", 1)[1].lower().strip("[]")

    indicators: list[dict] = []
    if not display or not domain:
        return {
            "sender_brand_mismatch": False,
            "matched_brand": None,
            "indicators": indicators,
            "risk_score": 0,
            "risk_level": "LOW",
            "reason": "insufficient sender metadata to assess",
        }

    matched = _brand_token_in(display)
    if not matched:
        return {
            "sender_brand_mismatch": False,
            "matched_brand": None,
            "indicators": indicators,
            "risk_score": 0,
            "risk_level": "LOW",
            "reason": "display name does not claim a monitored brand",
        }

    profile = _p.BRAND_PROFILES[matched]
    official = tuple(profile["official"])
    trusted = False
    for dom in official:
        if domain == dom or domain.endswith("." + dom):
            trusted = True
            break
    if not trusted:
        # Fall back: the address mentions the brand itself (foo@sbi.xyz).
        trusted = re.search(r"(?<!\w)" + re.escape(matched) + r"(?!\w)", domain)

    if trusted:
        return {
            "sender_brand_mismatch": False,
            "matched_brand": matched,
            "indicators": indicators,
            "risk_score": 0,
            "risk_level": "LOW",
            "reason": f"'{matched}' display name matches its declared domain",
        }

    score = 22.0
    indicators.append({
        "indicator": "sender_brand_mismatch",
        "severity": "medium",
        "score": score,
        "reason": (f"The sender's display name claims to be '{matched}', but "
                   f"the actual sender domain is '{domain}', which '{matched}' "
                   "does not officially own. Brand names in the display name "
                   "of a foreign domain is a classic phishing / BEC pattern."),
        "evidence": f"display=brand '{matched}', sender domain={domain}",
    })
    return {
        "sender_brand_mismatch": True,
        "matched_brand": matched,
        "indicators": indicators,
        "risk_score": int(round(score)),
        "risk_level": "MEDIUM",
        "reason": "display-name brand does not match the sender domain",
    }


__all__ = ["assess_sender"]