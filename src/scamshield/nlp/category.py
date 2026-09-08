"""Scam-type classification for the ScamShield message engine.

The category is chosen from the fired indicators using a priority table. Each
scam type maps to the "strongest evidence" — the indicator that most reliably
identifies that type. Types are tested in priority order; the first match whose
primary indicator fired wins. If none match or everything is benign, we return
"safe" (or "other" if there is some risk but no clear family).
"""

from __future__ import annotations

from . import patterns as _p


PRIMARY_INDICATOR: dict[str, str] = {
    "fake_kyc": "kyc_request",
    "upi_payment": "upi_payment_request",
    "phishing": "suspicious_link",
    "bank_impersonation": "bank_impersonation",
    "government_impersonation": "government_impersonation",
    "credential_theft": "credential_request",
    "fake_customer_care": "customer_care",
    "job_scam": "job_offer",
    "investment_scam": "investment_offer",
    "loan_scam": "loan_offer",
    "delivery_scam": "delivery_package",
    "lottery_prize": "prize_lottery",
    "social_media_impersonation": "social_impersonation",
}

# Priority order: more specific / distinctive types first. A specific family
# (e.g. job offer, loan) wins over the generic "upi_payment" when both fire.
PRIORITY: tuple[str, ...] = (
    "fake_kyc",
    "lottery_prize",
    "bank_impersonation",
    "credential_theft",
    "government_impersonation",
    "fake_customer_care",
    "job_scam",
    "investment_scam",
    "loan_scam",
    "delivery_scam",
    "social_media_impersonation",
    "upi_payment",
    "phishing",
)


def predict_category(detections: dict[str, dict], is_scam: bool,
                     fired_indicators: list[str]) -> str:
    """Return a category string from the spec (or "safe" / "other")."""
    if not is_scam:
        # Even a "safe" message may still be lowered by cues; if no strong scam
        # signal, it is safe.
        return "safe"

    for cat in PRIORITY:
        prim = PRIMARY_INDICATOR[cat]
        if detections.get(prim, {}).get("present"):
            return cat

    # No primary family fired but the message still scored as a scam (e.g. only
    # urgency + threat + sensitive-info without a clear family).
    return "other"
