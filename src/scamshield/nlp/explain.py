"""Explainability and safety recommendations for the ScamShield message engine.

For each fired indicator we produce a human-readable explanation. Then, based on
the detected scam category (and indicators), we emit contextual recommendations.
"""

from __future__ import annotations

EXPLANATIONS: dict[str, str] = {
    "urgency": "The message pressures the recipient to act immediately.",
    "threat": "The message threatens account blocking, legal action or loss of access.",
    "kyc_request": "The message asks the user to complete or update KYC/identity verification.",
    "otp_request": "The message asks for an OTP (one-time password), which only the user must hold.",
    "credential_request": "The message asks for a PIN, password, or card details.",
    "upi_payment_request": "The message asks the user to make a payment or reveal a UPI/payment detail.",
    "prize_lottery": "The message claims the user has won a prize or lottery.",
    "job_offer": "The message offers a job, often asking for money or personal details.",
    "investment_offer": "The message promises unusually high or 'guaranteed' returns on investment.",
    "loan_offer": "The message offers a quick loan and may ask for an advance / processing fee.",
    "customer_care": "The message impersonates customer care / helpdesk staff.",
    "delivery_package": "The message asks for payment or details related to a parcel/delivery.",
    "bank_impersonation": "The message impersonates a bank and requests sensitive banking data.",
    "government_impersonation": "The message impersonates a government or tax body.",
    "social_impersonation": "The message impersonates a known person (relative/friend) or an account.",
    "sensitive_info_request": "The message asks for personal or financial information.",
    "reward_claim": "The message claims money was received or a reward/cashback is due.",
    "suspicious_link": "The message contains a link and/or urges the user to click one.",
}


def build_explanations(fired_indicators: list[str],
                       severities: dict[str, str]) -> list[dict]:
    """Return a list of {indicator, severity, reason} for every fired indicator."""
    out = []
    for name in fired_indicators:
        out.append({
            "indicator": name,
            "severity": severities.get(name, "low"),
            "reason": EXPLANATIONS.get(name, "A risk pattern was detected."),
        })
    return out


# Category-specific recommendations (contextual)
CATEGORY_RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
    "fake_kyc": (
        "Verify KYC requests through your bank's official website or app only.",
        "Never share OTP, PIN, or password for KYC.",
        "Do not click links in such messages.",
    ),
    "upi_payment": (
        "Never send money to an unknown UPI ID.",
        "Do not approve UPI collect requests from unknown senders.",
        "Contact your payment app's official support to verify any refund/payment claim.",
    ),
    "phishing": (
        "Do not click suspicious links.",
        "Visit the official website by typing the address yourself.",
        "Ignore requests to enter passwords or card details via links.",
    ),
    "bank_impersonation": (
        "Never share OTP, PIN, CVV, or card number over calls/messages.",
        "Contact your bank using the official number/website.",
        "Banks never ask you to share passwords or verify details via links.",
    ),
    "government_impersonation": (
        "Government/tax bodies never ask for payments via personal links or UPI.",
        "Verify any tax/refund request on the official government portal.",
        "Report suspected income-tax or Aadhaar fraud to the authorities.",
    ),
    "credential_theft": (
        "Never share OTP, PIN, passwords, or card details.",
        "Change your passwords if you suspect exposure.",
        "Do not enter credentials on unknown sites.",
    ),
    "fake_customer_care": (
        "Contact the company/organization using official contact methods.",
        "Real customer care never asks for OTP or PIN.",
        "Do not call numbers given in such messages.",
    ),
    "job_scam": (
        "Verify job offers independently on the company's official website.",
        "Legitimate employers never ask you to pay a registration or security fee.",
        "Do not share Aadhaar/bank details for a job without verification.",
    ),
    "investment_scam": (
        "Be suspicious of guaranteed or unusually high returns.",
        "Verify investment schemes with SEBI-registered advisors.",
        "Never send money to unknown accounts for 'returns'.",
    ),
    "loan_scam": (
        "Real lenders do not ask for an upfront processing fee.",
        "Verify the loan provider independently.",
        "Never share bank details for a 'pre-approved' loan.",
    ),
    "delivery_scam": (
        "Do not pay extra customs/delivery fees via unknown links.",
        "Track your parcel on the courier's official app/website.",
        "Ignore demands to pay via QR or UPI for delivery.",
    ),
    "lottery_prize": (
        "Legitimate prizes are not taxed in advance via UPI or links.",
        "Do not pay any 'processing fee' to claim a prize.",
        "Ignore unsolicited lottery winnings.",
    ),
    "social_media_impersonation": (
        "Verify money requests from friends/relatives over a trusted call.",
        "Do not transfer money based on an urgent message alone.",
        "Report impersonation of you or others on social platforms.",
    ),
}

COMMON_RECOMMENDATIONS: tuple[str, ...] = (
    "Report the message to the relevant platform/authority.",
    "Do not respond, and block the sender if possible.",
)


def build_recommendations(scam_type: str) -> list[str]:
    """Return a list of actionable recommendations for the detected scam type."""
    recs = list(CATEGORY_RECOMMENDATIONS.get(scam_type, ()))
    recs.extend(COMMON_RECOMMENDATIONS)
    return recs
