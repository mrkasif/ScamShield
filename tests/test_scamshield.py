"""Unit tests for the ScamShield message analysis engine.

Run with:
    python -m pytest tests/test_scamshield.py -v

These tests cover the explainable rule-based detection layer. They verify:
  * obvious phishing / fake KYC / OTP / UPI / job / investment / delivery /
    lottery scams are flagged;
  * legitimate bank, delivery, job and conversation messages are NOT flagged;
  * Hindi, Marathi and Hinglish examples work;
  * the risk score is always within 0-100;
  * results are deterministic (reproducible);
  * URL extraction works.
"""

import sys
from pathlib import Path

import pytest

# Make the src layout importable when tests run from the repo root.
ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scamshield.nlp import analyze_message  # noqa: E402


# ---------------------------------------------------------------------------
# SCAM messages that should be flagged
# ---------------------------------------------------------------------------

SCAM_MESSAGES = [
    ("Your KYC has expired. Verify immediately at this link.", "kyc_request"),
    ("Your bank account is blocked. Share your OTP to unblock it now.", "otp_request"),
    ("URGENT: your SBI UPI is on hold. Confirm your PIN at bit.ly/verify-now to resume.",
     "upi_payment_request"),
    ("Congratulations! You have won the KBC lottery of Rs 25 lakh. Send the processing fee to claim.",
     "prize_lottery"),
    ("Work from home job: earn Rs 5000 per day. Pay Rs 499 registration fee to start.",
     "job_offer"),
    ("Guaranteed 100% return on your investment. Deposit funds via UPI today.",
     "investment_offer"),
    ("Your loan is pre-approved. Pay the processing fee first to receive it.",
     "loan_offer"),
    ("Your parcel is stuck in customs. Pay the extra delivery charge at this link to release it.",
     "delivery_package"),
    ("This is your bank. We noticed suspicious activity. Share your ATM PIN to secure your account.",
     "bank_impersonation"),
    ("Income tax department: your refund is pending. Verify your PAN on this official-looking link.",
     "government_impersonation"),
]


@pytest.mark.parametrize("text,expected_indicator", SCAM_MESSAGES)
def test_scam_is_flagged(text, expected_indicator):
    result = analyze_message(text)
    assert result["is_scam"] is True, f"expected scam for: {text}"
    assert result["risk_score"] >= 50, f"score too low for scam: {result['risk_score']}"
    assert expected_indicator in result["detected_indicators"], \
        f"expected {expected_indicator} in {result['detected_indicators']}"


# ---------------------------------------------------------------------------
# LEGITIMATE messages that must NOT be flagged as scams
# ---------------------------------------------------------------------------

SAFE_MESSAGES = [
    "SBI: Rs.250.00 credited to a/c XX12 on 06-Sep. Avl Bal Rs.5,000.00. Do not share OTP.",
    "Hi mum, I reached campus. Call you after class.",
    "Your parcel has been delivered successfully.",
    "Your train ticket has been booked successfully.",
    "Meeting moved to 4pm tomorrow in college lab.",
    "Your payment of Rs.899 has been received. Thank you.",
    "Thank you for your order. You can track it in the official app.",
]


@pytest.mark.parametrize("text", SAFE_MESSAGES)
def test_safe_message_not_flagged(text):
    result = analyze_message(text)
    assert result["is_scam"] is False, f"expected safe for: {text}"
    assert result["risk_score"] <= 49, f"score too high for safe: {result['risk_score']}"


# ---------------------------------------------------------------------------
# Multilingual examples (Hindi, Marathi, Hinglish)
# ---------------------------------------------------------------------------

MULTILINGUAL_SCAM = [
    ("आपका केवाईसी समाप्त हो गया है। खाता बंद होने से पहले लिंक पर अपडेट करें।", "fake_kyc"),
    ("तुमचे बँक खाते ब्लॉक होणार आहे. OTP द्या आणि लिंक उघडा.", "bank_impersonation"),
    ("Aapka KYC expire ho gaya hai, account block hone se pehle link open karo.", "fake_kyc"),
    ("Jaldi karo, aapka account block ho jayega. OTP batao.", "other"),
    # Hindi / Marathi lottery + job / Hinglish prize + parcel / utility scam
    ("आपने केबीसी में ₹25 लाख जीते। टैक्स भरने के लिए लिंक पर जाएं।", "lottery_prize"),
    ("तुम्ही लॉटरी जिंकली. टॅक्स भरा http://192.0.2.10/login.", "lottery_prize"),
    ("घरून जॉब: दिवसाला ₹1800. फी भरा.", "job_scam"),
    ("Aapko 25 lakh jeete hai, processing fee UPI pe bhejo.", "lottery_prize"),
    ("Aapka parcel customs me atka hai, Rs 35 pay karke release karo http://bit.ly/xyz123",
     "delivery_scam"),
    ("Your electricity bill was overdue. Pay now to avoid disconnection at this link.",
     "government_impersonation"),
]


@pytest.mark.parametrize("text,expected_type", MULTILINGUAL_SCAM)
def test_multilingual_scam_detected(text, expected_type):
    result = analyze_message(text)
    assert result["is_scam"] is True, f"expected multilingual scam for: {text}"
    assert result["risk_score"] >= 50
    if expected_type != "other":
        assert result["scam_type"] == expected_type, (
            f"expected type {expected_type}, got {result['scam_type']}"
        )


# Verify that reasonable Urdu-free Hindi safe text is not flagged.
MULTILINGUAL_SAFE = [
    "आपका बैंक खाता। कृपया अधिकृत ऐप का उपयोग करें।",
    "मैत्रीपूर्ण संदेश",
]


@pytest.mark.parametrize("text", MULTILINGUAL_SAFE)
def test_multilingual_safe_not_flagged(text):
    result = analyze_message(text)
    assert result["is_scam"] is False


# ---------------------------------------------------------------------------
# Risk score bounds & determinism
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [m[0] for m in SCAM_MESSAGES] + SAFE_MESSAGES)
def test_risk_score_bounds(text):
    result = analyze_message(text)
    assert 0 <= result["risk_score"] <= 100


def test_deterministic():
    texts = ["Your KYC has expired. Verify immediately at this link.",
             "Hi mum, I reached campus. Call you after class."]
    for t in texts:
        assert analyze_message(t) == analyze_message(t)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

def test_url_extraction():
    result = analyze_message("Verify your account at https://bit.ly/kyc99 right now.")
    assert isinstance(result["detected_urls"], list)
    assert any("bit.ly" in u for u in result["detected_urls"])


def test_no_url_when_none():
    result = analyze_message("Just a normal message with no links.")
    assert result["detected_urls"] == []


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

def test_result_structure():
    r = analyze_message("Your KYC has expired. Verify immediately at this link.")
    for key in ("is_scam", "risk_score", "risk_level", "scam_type",
                "confidence", "detected_indicators", "detected_urls",
                "explanations", "recommendations"):
        assert key in r, f"missing key {key}"
    assert isinstance(r["explanations"], list)
    assert isinstance(r["recommendations"], list)
