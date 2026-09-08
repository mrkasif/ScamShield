"""Weighted, transparent risk scoring for the ScamShield message engine.

Design
------
Each risk indicator has a base weight (its "importance") and a severity
multiplier (low / medium / high). The raw score is the sum over all detected
indicators of (weight * severity_multiplier).

Class-scoring
-------------
Certain threat *families* carry a strong signal even when a single related
indicator fires (e.g. a message that both asks for an OTP and mentions KYC is
clearly fraudulent). We therefore add small "combination bonuses" when related
indicators fire together, and a base family signal.

Penalties
---------
Protective / safe cues (legitimate-channel markers, "never share OTP" advice,
warnings) lower the score because they indicate a legitimate sender.

Normalization
-------------
The raw summed score is clamped to 0-100 and rounded. Deterministic, no
randomness: the same input always produces the same score.

Risk levels (per the spec):
  0-24   LOW
  25-49  MEDIUM
  50-74  HIGH
  75-100 CRITICAL
"""

from __future__ import annotations

from . import patterns as _p


# Severity multipliers
SEVERITY_MULTIPLIER: dict[str, float] = {
    "low": 1.0,
    "medium": 1.6,
    "high": 2.2,
}

# Base weight per indicator (importance of a single detection)
WEIGHTS: dict[str, float] = {
    "urgency": 4.0,
    "threat": 8.0,
    "kyc_request": 10.0,
    "otp_request": 12.0,
    "credential_request": 14.0,
    "upi_payment_request": 10.0,
    "prize_lottery": 12.0,
    "job_offer": 7.0,
    "investment_offer": 10.0,
    "loan_offer": 8.0,
    "customer_care": 6.0,
    "delivery_package": 7.0,
    "bank_impersonation": 9.0,
    "government_impersonation": 9.0,
    "social_impersonation": 9.0,
    "sensitive_info_request": 11.0,
    "reward_claim": 7.0,
    "suspicious_link": 9.0,
}

# Combination bonuses: when BOTH indicators fire, add this onto the score.
# This captures the fact that a request for credentials alongside pressure is
# far more suspicious than either alone.
COMBINATIONS: tuple[tuple[str, str, float], ...] = (
    ("otp_request", "kyc_request", 15.0),
    ("otp_request", "bank_impersonation", 15.0),
    ("otp_request", "threat", 12.0),
    ("credential_request", "bank_impersonation", 14.0),
    ("upi_payment_request", "reward_claim", 12.0),
    ("upi_payment_request", "suspicious_link", 8.0),
    ("upi_payment_request", "threat", 10.0),
    ("kyc_request", "suspicious_link", 10.0),
    ("job_offer", "upi_payment_request", 12.0),
    ("investment_offer", "upi_payment_request", 12.0),
    ("loan_offer", "upi_payment_request", 12.0),
    ("prize_lottery", "upi_payment_request", 12.0),
    ("social_impersonation", "upi_payment_request", 12.0),
    ("delivery_package", "upi_payment_request", 10.0),
    ("customer_care", "credential_request", 12.0),
    ("customer_care", "otp_request", 12.0),
    ("bank_impersonation", "credential_request", 14.0),
    ("bank_impersonation", "threat", 10.0),
    ("government_impersonation", "credential_request", 12.0),
    ("delivery_package", "suspicious_link", 10.0),
    ("prize_lottery", "suspicious_link", 10.0),
    ("government_impersonation", "upi_payment_request", 8.0),
    ("government_impersonation", "sensitive_info_request", 10.0),
    ("bank_impersonation", "upi_payment_request", 8.0),
    ("job_offer", "sensitive_info_request", 10.0),
)

# Systematic "family + money/credential" bonus: the canonical Indian scam pattern
# is an unsolicited *offer/claim* (prize, job, loan, investment, parcel, etc.)
# that then asks the user to pay money or share credentials. When ANY family
# indicator fires together with ANY money/credential indicator, we add a strong,
# deterministic bonus so these decisively score as HIGH.
FAMILY_INDICATORS: tuple[str, ...] = (
    "job_offer", "investment_offer", "loan_offer", "prize_lottery",
    "delivery_package", "bank_impersonation", "government_impersonation",
    "social_impersonation", "customer_care",
)
MONEY_CRED_INDICATORS: tuple[str, ...] = (
    "upi_payment_request", "credential_request", "otp_request", "reward_claim",
    "sensitive_info_request",
)
FAMILY_MONEY_BONUS: dict[int, float] = {
    0: 0.0,
    1: 18.0,
    2: 26.0,
    3: 32.0,
}

# Safe / protective cues reduce the score (negative contribution)
SAFE_CUE_PENALTY: float = 18.0

# Score that counts as "scam" (used to set is_scam and risk level boundaries)
SCAM_THRESHOLD: float = 50.0

# Indicators that, when a message is a *clear benign confirmation*, indicate an
# immediate action is being requested (i.e. would override the benign context).
# Their presence prevents the transaction-guard from applying.
ACTION_PRESSURE_INDICATORS: tuple[str, ...] = (
    "urgency",
    "threat",
    "suspicious_link",
    "otp_request",
    "credential_request",
    "upi_payment_request",
)

# Phrases that mark a message as an ordinary, legitimate confirmation /
# notification (no action requested). Downgrades a risk score strongly.
TRANSACTIONAL_PHRASES: tuple[str, ...] = (
    "credited to", "credited to a/c", "credited to your account", "credited rs",
    "debited from", "debited from a/c", "payment of", "payment successful",
    "has been delivered", "has been shipped", "is shipped", "delivered successfully",
    "ticket has been booked", "booked successfully", "has been booked",
    "payment received", "received payment", "your payment", "emi of",
    "auto-debited", "bill was paid", "bill paid", "cashback of",
    "recharge", "refund", "confirmed for", "appointment confirmed",
)


def _risk_level(score: float) -> str:
    if score < 25:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def compute_score(detections: dict[str, dict], text: str) -> dict:
    """Compute the risk score + level + confidence from detector results.

    Returns: {raw_score (0-100 float), risk_score (int), risk_level, is_scam,
    confidence (float 0-100), fired_indicators: [names]}
    """
    fired = [name for name, d in detections.items() if d["present"]]

    raw = 0.0
    for name in fired:
        sev = detections[name]["severity"]
        raw += WEIGHTS.get(name, 0.0) * SEVERITY_MULTIPLIER.get(sev, 1.0)

    # Combination bonuses
    for a, b, bonus in COMBINATIONS:
        if a in fired and b in fired:
            raw += bonus

    # Systematic "family + money/credential" bonus
    family_fired = [f for f in fired if f in FAMILY_INDICATORS]
    money_cred_fired = [f for f in fired if f in MONEY_CRED_INDICATORS]
    if family_fired and money_cred_fired:
        raw += FAMILY_MONEY_BONUS.get(len(money_cred_fired),
                                      max(FAMILY_MONEY_BONUS.values()))

    # Safe-cue penalty
    norm = _normalize_lite(text)
    if any(_has(norm, cue) for cue in _p.SAFE_MARKERS):
        raw -= SAFE_CUE_PENALTY

    # Transactional-confirmation guard: ordinary legitimate notifications (money
    # credited/debited, package delivered, ticket booked, etc.) that do NOT ask
    # the user to act (no urgency/threat/link/credential/payment request) are
    # down-weighted very strongly so they are not misclassified as scams.
    if _is_transactional_confirmation(norm):
        if not any(d in fired for d in ACTION_PRESSURE_INDICATORS):
            raw -= 40.0
            # Also neutralise the bank-name / reward / OTP-rule contributions that
            # arise merely from mentioning the bank or the OTP rule.
            for weak in ("bank_impersonation", "reward_claim", "otp_request",
                         "sensitive_info_request"):
                if weak in fired:
                    raw -= WEIGHTS.get(weak, 0.0) * SEVERITY_MULTIPLIER.get(
                        detections[weak]["severity"], 1.0)
                    fired = [f for f in fired if f != weak]

    # Clamp to 0-100
    raw = max(0.0, min(100.0, raw))
    risk_score = int(round(raw))
    risk_score = max(0, min(100, risk_score))

    level = _risk_level(risk_score)
    is_scam = risk_score >= SCAM_THRESHOLD

    # Confidence heuristic: combine number of fired indicators + deviation from
    # the LOW/MEDIUM boundary. Simple, deterministic proxy for signal strength.
    if fired:
        strength = min(1.0, raw / 100.0)
        # boost slightly with number of indicators, capped
        count_boost = min(1.0, len(fired) / 6.0) * 0.15
        arr = (strength * 0.60) + (count_boost) + 0.25
        confidence = max(0.0, min(100.0, arr * 100.0))
    else:
        confidence = 0.0

    confidence = round(confidence, 1)

    return {
        "raw_score": round(raw, 2),
        "risk_score": risk_score,
        "risk_level": level,
        "is_scam": is_scam,
        "confidence": confidence,
        "fired_indicators": fired,
    }


def _normalize_lite(t: str) -> str:
    if not t:
        return ""
    return re_sub_ws(t.strip().lower())


def re_sub_ws(s: str) -> str:
    import re
    return re.sub(r"\s+", " ", s)


def _has(text: str, phrase: str) -> bool:
    return phrase in text


def _is_transactional_confirmation(norm: str) -> bool:
    """True when the message reads like a routine transaction notification.

    Examples: funds credited/debited, payment successful, parcel delivered,
    ticket booked, appointment confirmed. Such messages describe an event that
    already happened; they do not ask the user to take action.
    """
    return any(_has(norm, p) for p in TRANSACTIONAL_PHRASES)
