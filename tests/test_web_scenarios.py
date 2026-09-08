"""End-to-end scenarios verified through the web/API layer.

Every assertion is based on REAL, measured analyzer output (verified while the
evaluation was built). The Flask test client wraps the real ScamShield engines -
no fake data, no fabricated statistics.
"""
from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
for _p in (_REPO_ROOT, _REPO_ROOT / "src"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
sys.path.insert(0, str(_REPO_ROOT))

from web.app import create_app  # noqa: E402


FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "qr"
SUSPICIOUS_URL = "https://secure-sbi-verify.example.com/login"


@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _msg(client, text):
    return client.post("/api/analyze/message", json={"message": text}).get_json()


def _url(client, value):
    return client.post("/api/analyze/url", json={"url": value}).get_json()


def _upi(client, value):
    return client.post("/api/analyze/upi", json={"upi": value}).get_json()


def _qr(client, filename: str):
    return client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO((FIXTURES / filename).read_bytes()), filename)},
        content_type="multipart/form-data",
    ).get_json()


def _chain(client, stages):
    return client.post("/api/analyze/chain", json={"stages": stages}).get_json()


# ---------------------------------------------------------------------------
# SAFE scenarios
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Your SBI account received a credit of Rs 500. Balance is Rs 25000.",
    "Your order #12345 has been dispatched and will be delivered tomorrow by BlueDart.",
])
def test_safe_messages_not_flagged(client, text) -> None:
    r = _msg(client, text)
    assert r["success"] is True
    assert r["is_suspicious"] is False


def test_legitimate_url_not_flagged(client) -> None:
    r = _url(client, "https://www.sbi.co.in/personal")
    assert r["success"] is True
    assert r["is_suspicious"] is False
    assert r["risk_score"] == 0


# ---------------------------------------------------------------------------
# SCAM scenarios (measured real outputs)
# ---------------------------------------------------------------------------

def test_fake_kyc_message(client) -> None:
    r = _msg(client, "Your KYC has expired. Click now to verify.")
    assert r["is_suspicious"] is True
    assert r["scam_type"] in ("fake_kyc", "phishing", "other")
    assert "kyc_request" in r["indicators"]


def test_otp_credential_request_message(client) -> None:
    r = _msg(client, "Enter your OTP and Aadhaar to unblock your account.")
    assert r["is_suspicious"] is True
    assert "otp_request" in r["indicators"]


def test_prize_refund_message(client) -> None:
    r = _msg(client, "Congratulations! You won Rs 1,00,000. Pay a small processing fee to claim your prize now.")
    assert r["is_suspicious"] is True
    assert r["scam_type"] == "lottery_prize"


def test_fake_customer_care_message(client) -> None:
    r = _msg(client, "We are from customer care. Your account has an issue. Share your debit card number and OTP to resolve it.")
    assert r["is_suspicious"] is True
    assert r["scam_type"] in ("bank_impersonation", "fake_customer_care", "other")


def test_job_scam_message(client) -> None:
    r = _msg(client, "Join our work-from-home job. No experience needed. Pay registration fee of Rs 500 to start earning.")
    assert r["is_suspicious"] is True
    assert r["scam_type"] == "job_scam"


# ---------------------------------------------------------------------------
# URL scenarios
# ---------------------------------------------------------------------------

def test_phishing_url(client) -> None:
    r = _url(client, SUSPICIOUS_URL)
    assert r["is_suspicious"] is True
    assert r["risk_score"] >= 50


def test_typosquatting_url_flagging(client) -> None:
    r = _url(client, "http://paypai.com/verify")
    assert r["success"] is True
    assert r["risk_score"] >= 25
    assert "possible_brand_typosquatting" in r["indicators"]


def test_suspicious_subdomain_cluster(client) -> None:
    r = _url(client, "http://secure.login.verify.account.example.com/")
    assert r["is_suspicious"] is True
    assert r["risk_score"] >= 50


def test_suspicious_query_parameters(client) -> None:
    r = _url(client, "http://example.com/login?redirect=http://evil.example")
    assert r["success"] is True
    assert "suspicious_redirect_parameter" in r["indicators"] or \
        r["risk_score"] >= 25


def test_legitimate_url_clean(client) -> None:
    r = _url(client, "https://www.onlinesbi.com/index.html")
    assert r["is_suspicious"] is False
    assert r["risk_score"] == 0


# ---------------------------------------------------------------------------
# QR scenarios (real fixture images)
# ---------------------------------------------------------------------------

def test_qr_safe_upi(client) -> None:
    r = _qr(client, "upi_normal.png")
    assert r["success"] is True
    assert r["engine_results"]["qr"]["content_type"] == "upi"
    assert r["is_suspicious"] is False


def test_qr_suspicious_url(client) -> None:
    r = _qr(client, "url_suspicious.png")
    assert r["success"] is True
    assert r["is_suspicious"] is True


def test_qr_suspicious_upi(client) -> None:
    r = _qr(client, "upi_refund_scan.png")
    assert r["success"] is True
    assert r["is_suspicious"] is True
    assert "refund_reward_prize_language" in \
        (r.get("engine_results", {}).get("qr", {}).get("upi_analysis", {}) or {}).get("indicators", [])


def test_qr_invalid_image(client) -> None:
    r = client.post(
        "/api/analyze/qr",
        data={"qr_image": (io.BytesIO(b"not an image"), "bad.png")},
        content_type="multipart/form-data",
    ).get_json()
    assert r["success"] is False
    assert r["status"] == "ERROR"


def test_qr_no_qr_present(client) -> None:
    r = _qr(client, "no_qr_blank.png")
    assert r["status"] == "NOT DECODED"
    assert r["is_suspicious"] is False


# ---------------------------------------------------------------------------
# UPI scenarios
# ---------------------------------------------------------------------------

def test_upi_normal_merchant(client) -> None:
    r = _upi(client, "upi://pay?pa=merchant@upi&pn=Store&am=60&cu=INR")
    assert r["success"] is True
    assert r["is_suspicious"] is False


def test_upi_suspicious_refund_claim(client) -> None:
    r = _upi(client, "upi://pay?pa=refund.prize@upi&am=50000&tn=Claim your refund prize now urgently")
    assert r["is_suspicious"] is True
    assert r["scam_type"] == "upi_payment"


# ---------------------------------------------------------------------------
# CHAIN scenarios (real analyzer outputs through the web layer)
# ---------------------------------------------------------------------------

def test_chain_message_to_suspicious_url(client) -> None:
    stages = [
        _msg(client, "Your KYC has expired. Verify now: " + SUSPICIOUS_URL),
        _url(client, SUSPICIOUS_URL),
    ]
    r = _chain(client, stages)
    assert r["success"] is True
    assert r["is_suspicious"] is True
    assert r["classification"] == "multi_stage_scam"
    assert r["chain_pattern"] == "kyc_phishing"


def test_chain_message_url_credential(client) -> None:
    stages = [
        _msg(client, "Your KYC has expired. Verify now: " + SUSPICIOUS_URL),
        _url(client, SUSPICIOUS_URL),
        _msg(client, "Enter your OTP and Aadhaar to unblock your account."),
    ]
    r = _chain(client, stages)
    assert r["success"] is True
    assert r["is_suspicious"] is True
    assert r["classification"] == "multi_stage_scam"


def test_chain_qr_to_url(client) -> None:
    stages = [
        _qr(client, "url_suspicious.png"),
        _url(client, SUSPICIOUS_URL),
    ]
    r = _chain(client, stages)
    assert r["success"] is True
    assert r["is_suspicious"] is True
    assert r["chain_pattern"] == "kyc_phishing"


def test_chain_scam_message_to_suspicious_upi(client) -> None:
    stages = [
        _msg(client, "Pay your refund fee now: upi://pay?pa=refund.prize@upi&am=500&tn=claim"),
        _upi(client, "upi://pay?pa=refund.prize@upi&am=500&tn=claim refund prize"),
    ]
    r = _chain(client, stages)
    assert r["success"] is True
    assert r["is_suspicious"] is True
    assert r["classification"] == "multi_stage_scam"
    assert r["chain_pattern"] == "prize_refund"